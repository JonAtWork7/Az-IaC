# Running Azure Local Like a Cloud: Notes From Setting It Up

Azure Local (formerly Azure Stack HCI) is positioned as Azure-native
control for on-prem hardware. The reality, after standing it up across
multiple datacenters, environments, and clusters, is that the
"Azure-native" part only holds up if you build the platform around the
same disciplines you would expect in the public cloud. The notes below
describe the patterns I have found necessary to get there — what worked,
what did not, and where the published tooling is not yet enough on its
own.

---

## 1. Start With the Modules: AVMs Will Need Forking

The first practical decision is how to express Azure Local in Terraform,
and that decision is not as clean as it appears in the marketing.

Microsoft publishes **Azure Verified Modules (AVM)** for several Azure
Local resource types, and they are the right starting point. Pin the
version, enable telemetry, and use them as written wherever they cover
your case. They will save real time on the resources they support well.

What I have found in practice, however, is that **forking the existing
AVMs is still required** if you intend to run Azure Local at any
meaningful scope. The reasons recur:

- The Azure Local API surface (`Microsoft.AzureStackHCI/*`,
  `Microsoft.HybridCompute/*`, `Microsoft.ExtendedLocation/*`) moves
  faster than the public AVMs do, and important fields land in the API
  before they land in the module.
- Several AVMs assume public-cloud defaults that do not apply to Azure
  Local — networking, identity, extension publishers, and
  custom-location handling are the most common offenders.
- Organizational constraints (naming, required tags, enforced policy
  parameters, allowed images, locked-down extension sources) need to be
  baked into the module, not bolted on at every call site.

The pragmatic posture is: use AVMs as the upstream, fork them into your
own module set, and treat that fork as a maintained product. Document
the delta from upstream so you can pull in fixes deliberately. Do not
attempt to drive a complete Azure Local platform off unmodified public
AVMs — you will spend more time working around them than you will save
adopting them.

### A Note on Distribution: Private Terraform Registry

For a small team with a handful of clusters, vendoring the forked
modules into the same repository works. Once you cross into a larger
organization — multiple platform teams, multiple consumer repositories,
versioned releases of shared modules — that approach becomes painful.

In that situation I would recommend standing up a **private Terraform
registry** for your Azure Local resource types: forked AVMs, internal
wrappers (VM, lnet, AKS, tags, policy, maintenance), and any
opinionated composite modules. Consumers reference them by version,
upgrades are explicit, and the platform team controls release cadence.

The mechanics of running a private registry — choice of product,
authentication, CI publishing, semantic versioning policy — are out of
scope for this document. The point I want to make here is only that
**if your environment is large enough to need this, plan for it
early**; retrofitting module distribution after dozens of consumers
have hardcoded local paths is significantly harder than starting with
versioned references.

### `azapi`, Not `azurerm`

Whether you are using AVMs, your forks, or writing resources directly,
Azure Local belongs to `azapi_resource` (or modules that wrap it).
`azurerm_virtual_machine` and similar resources do not target the Azure
Local provider namespace and should not be used. Working directly
against the API also means new fields are reachable the day Microsoft
ships them, without waiting for a provider release — which, given how
often Azure Local APIs change, matters.

```hcl
resource "azapi_resource" "vm" {
  type      = "Microsoft.AzureStackHCI/virtualMachineInstances@2024-01-01"
  parent_id = azapi_resource.machine.id
  name      = "default"
  body      = jsonencode({ properties = { ... } })
}
```

### Everything Else Belongs in Code Too

With the module question settled, the rest of the platform follows:

- **Clusters, custom locations, Arc resource bridges** — declared in
  Terraform, not configured through the portal.
- **Logical networks (lnets)** — IP pools, gateways, DNS, VLANs.
- **VMs** — Windows and Linux, with disks, NICs, OS profiles, domain
  join, and post-deploy guest configuration.
- **AKS on Azure Local** — node pools, networking, add-ons.
- **Azure Site Recovery** — vault, Hyper-V site, replication policy,
  per-VM protection.
- **Azure Policy** — assignments and initiatives at the right scope.
- **Maintenance configurations and assignments** — patch windows
  attached to the right VMs automatically.
- **Tags** — through a single tagging module, so every resource gets
  the same well-known keys.

The benefit is straightforward: the entire on-prem footprint is
reviewable in a pull request, and drift is detected by `terraform plan`
rather than by an outage.

---

## 2. YAML for Humans, HCL for Machines

VM and network requests do not start as Terraform. They start as small
declarative **YAML files** describing intent, which a generator
converts into typed module calls. This separation has been valuable in
practice: application teams can read and write YAML without learning
HCL, and reviewers see a small, structured diff rather than a wall of
provider syntax.

```yaml
# vms/app-web-01.yaml
name: app-web-01
os: windows
cpu: 4
ram_gb: 16
disks:
  - { name: data, size_gb: 100 }
lnet: lnet-prod-app-vlanXXX
maintenance_window: prod-saturday-night
tags:
  service: storefront
  team: platform-engineering
  ansible-managed: "true"
```

The generator emits a module call with the correct conventions,
defaults, naming, and tag set already applied:

```hcl
module "app_web_01" {
  source  = "app.example/.../modules/azl_vm"
  version = "~> 3.0"

  name             = "app-web-01"
  os               = "windows"
  cpu              = 4
  memory_gb        = 16
  data_disks       = [{ name = "data", size_gb = 100 }]
  logical_network  = module.lnets["lnet-prod-app-vlanXXX"]
  maintenance_tag  = "prod-saturday-night"
  tags             = module.tags.value
}
```

The same pattern drives subnets, NSGs, and platform-wide settings,
captured in YAML under a single `global/` and `networking/` tree.

---

## 3. Logical Networks: a Naming Convention That Survives Scale

Logical network names should encode the facts a reader needs at a
glance: address space, location, environment, purpose, and VLAN. A
rigid pattern sorts predictably, greps cleanly, and makes downstream
automation (dropdowns, dashboards, audits) straightforward.

```text
lnet-<addr>-<cidr>-<dc>-<env>-<purpose>-vlan<id>
                  │      │       │
                  │      │       └─ short business purpose
                  │      └─ test | nprd | prod
                  └─ datacenter code
```

Networks are created from YAML, validated against the VLAN registry,
and wired into the lnet module. CIDR, gateway, and DNS are derived
from a single source so that the IP pool, default gateway, DNS list,
and any associated NSG rules stay consistent.

```yaml
# networking/lnets/prod/lnet-prod-app-vlanXXX.yaml
vlan: XXX
cidr: 10.x.y.0/24
gateway: 10.x.y.1
dns: [10.a.b.c, 10.a.b.d]
purpose: app
environment: prod
```

---

## 4. VMs With Guardrails Built In

Every VM that ships from this platform is expected to have:

- A name that conforms to a documented standard (environment prefix,
  application, role, instance number, NetBIOS-safe length).
- A required tag set: environment, service, team, datacenter, cluster,
  purpose, maintenance window, and an `ansible-managed` flag.
- Domain join, OS-specific defaults, and disk layout via the VM module.
- A maintenance window assignment at creation time, so the VM is not
  delivered in an unpatched state.
- For Arc-eligible VMs: Azure Monitor Agent, Azure Update Manager,
  Defender for Cloud, and Guest Configuration enabled by default.

The standard tag block is generated once and reused everywhere:

```hcl
module "tags" {
  source      = "./modules/tags"
  environment = "prod"
  datacenter  = "dcX"
  cluster     = "azl-cl01"
  service     = "storefront"
  team        = "platform-engineering"
  purpose     = "web-tier"
}
```

The resulting object is passed as the `tags` argument on the VM, lnet,
AKS, policy assignment, and maintenance assignment, so reporting, cost
allocation, and policy targeting all key off the same vocabulary.

---

## 5. Day-0 Agents via VM Extensions

A VM that boots without its required agents has to be tracked, chased,
and remediated later. To avoid that, every VM module call attaches its
**VM extensions** declaratively, so they install at provisioning time
rather than as a separate post-build step.

The same pattern applies to any agent — endpoint protection,
monitoring, configuration management bootstrap, role-specific scripts.
The agent's installer is the payload; the extension resource is the
delivery mechanism.

CrowdStrike Falcon is a useful concrete example because most
organizations require it on day zero and the vendor distributes a
Windows installer that fits cleanly into a custom script extension:

```hcl
# Day-0 EDR — CrowdStrike Falcon as a custom script extension
resource "azapi_resource" "ext_falcon" {
  type      = "Microsoft.HybridCompute/machines/extensions@2024-07-10"
  parent_id = azapi_resource.arc_machine.id
  name      = "CrowdStrike.Falcon"
  location  = var.location

  body = jsonencode({
    properties = {
      publisher          = "Microsoft.Compute"
      type               = "CustomScriptExtension"
      typeHandlerVersion = "1.10"
      settings = {
        fileUris = [
          # Internal artifact store (e.g. Azure Blob, internal file share, or
          # signed URL) — never the public CrowdStrike download.
          "https://artifacts.example.com/falcon/Install-Falcon.ps1"
        ]
      }
      protectedSettings = {
        commandToExecute = join(" ", [
          "powershell -ExecutionPolicy Bypass -File Install-Falcon.ps1",
          "-CID ${var.falcon_cid}",
          "-Tags 'env:${var.environment},dc:${var.datacenter}'"
        ])
        # CID and any install-time secrets come from a secret store,
        # never from plaintext variables.
      }
    }
  })
}
```

A few observations from running this in production:

- The Falcon installer is hosted internally rather than pulled from
  the public CrowdStrike URL. This is necessary both for change
  control (you decide when the agent version changes) and for hosts
  with restricted egress.
- The CID and any other install-time secrets come from a secret store,
  not from plaintext Terraform variables. `protectedSettings` keeps
  the rendered command out of the VM's plain extension settings.
- Grouping tags (`env:`, `dc:`, etc.) are passed at install time so
  the sensor lands in the right Falcon host group from its first
  check-in. Re-tagging after the fact has been a recurring source of
  manual cleanup, and this avoids it.
- Because the extension is a Terraform resource, drift is detectable.
  If the agent is uninstalled out-of-band, the next plan reinstalls it.
  Version upgrades roll out by changing the script URL or the
  `typeHandlerVersion`, opening a PR, and letting the fleet converge.

The same extension shape is used for other day-0 agents — the Azure
Monitor Agent installs via its own publisher/type rather than custom
script, but the lifecycle (declared with the VM, applied at
provisioning, drift-detected) is identical:

```hcl
# Same pattern, different payload — Azure Monitor Agent
resource "azapi_resource" "ext_ama" {
  type      = "Microsoft.HybridCompute/machines/extensions@2024-07-10"
  parent_id = azapi_resource.arc_machine.id
  name      = "AzureMonitorWindowsAgent"

  body = jsonencode({
    properties = {
      publisher               = "Microsoft.Azure.Monitor"
      type                    = "AzureMonitorWindowsAgent"
      autoUpgradeMinorVersion = true
      enableAutomaticUpgrade  = true
    }
  })
}
```

Treating extensions as part of the VM's definition rather than a
post-build checklist has been one of the higher-leverage changes in
this platform.

---

## 6. The `ansible-managed` Tag as the Handshake to Configuration Management

Day-0 agents handle bootstrap. Day-2 configuration — packages,
services, files, drift correction — belongs to **Ansible**. The bridge
between "Terraform built the VM" and "Ansible owns its config" is a
single tag that the VM module always emits:

```yaml
tags:
  ansible-managed: "true"
  ansible-roles: "iis,base-windows,monitoring"
```

That tag pair is the entire contract. Specifically:

1. **Dynamic inventory.** Ansible's Azure inventory plugin queries Arc
   for machines where `tags.ansible-managed == "true"` and groups them
   by other tags (`environment`, `datacenter`, `service`,
   `ansible-roles`). There are no static hosts files to maintain. A
   newly built VM appears in inventory on the next run, and only then.

   ```yaml
   # inventory.azure.yml
   plugin: azure.azcollection.azure_rm
   include_vm_resource_groups: ["*"]
   conditional_groups:
     prod_web: "tags['service'] == 'storefront' and tags['environment'] == 'prod'"
   keyed_groups:
     - prefix: env
       key: tags['environment']
     - prefix: role
       key: tags['ansible-roles']
   ```

2. **Role assignment from tags.** Playbooks read `ansible-roles` from
   the host's tags and apply the matching roles (`iis`, `sql`,
   `docker`, `base-linux`, and so on). The role list lives with the
   VM definition rather than in a separate spreadsheet, which has
   been the most reliable way I have found to keep Terraform and
   Ansible aligned over time.

   ```yaml
   - hosts: tag_ansible_managed_true
     tasks:
       - include_role:
           name: "{{ item }}"
         loop: "{{ (hostvars[inventory_hostname].tags['ansible-roles']
           | default('')).split(',') }}"
   ```

3. **Scheduled drift correction.** A scheduled job (AWX/Tower, GitHub
   Actions, or a pipeline) runs the playbook against the
   `tag_ansible_managed_true` group — typically in check mode for
   production and apply mode for non-production. Anything that has
   drifted is flagged or remediated.

4. **Decommission via tag removal.** Removing the tag, or destroying
   the VM in Terraform, drops the host from inventory on the next
   run. Stale entries do not accumulate.

The intent is that a single boolean tag connects every Terraform-built
VM to the configuration-management pipeline, so engineers can stay
focused on intent rather than on inventory mechanics.

---

## 7. Patching as a First-Class Resource

Maintenance windows are managed as Terraform resources rather than as
spreadsheet entries. The relevant points are:

- Windows are defined centrally — cadence, day, time, duration, and
  time zone — and reused.
- VMs opt in by tag, so assignment is deterministic and reviewable.
- Enforcement is delegated to **Azure Update Manager**, with periodic
  assessment turned on so reporting reflects reality rather than
  intent.
- Window selection accounts for **failover-partner gaps**: primary
  and secondary nodes of a cluster should never be patched in the
  same window, and a minimum cool-down between paired windows is
  enforced before a new VM can be assigned.

In practice the most useful piece has been the partner-gap check. It
is the kind of constraint that is easy to violate when assignments are
made by hand and easy to enforce when assignments are code-reviewed.

---

## 8. Disaster Recovery as Code (ASR)

Azure Site Recovery on Azure Local is fragile when configured through
the portal — the number of inter-related objects (vault, Hyper-V site,
fabric, replication policy, container mappings, network mappings,
protected items) makes click-driven setup easy to get subtly wrong and
hard to reproduce.

Managing it as code addresses that, but it is also where I have most
often had to fork upstream modules. The flow that has worked is:

1. Terraform creates the **Recovery Services vault** and the **Hyper-V
   site** representing the source cluster, along with the fabric and
   container objects that hang off them.
2. A **replication policy** (RPO, retention, app-consistent
   snapshot frequency) is declared once and reused across protected
   items.
3. Per-VM **protected items** are added with a single module call.
   Target resource group, network mapping, and managed disk type are
   explicit rather than inferred.
4. Test failovers are scheduled, documented, and tracked the same way
   any other change is — through pull requests and runbooks, not
   ad-hoc portal clicks.

Because the configuration is declarative, comparing what is protected
against what should be protected is a Terraform plan. That alone has
been worth the effort of moving ASR out of the portal.

---

## 9. Arc and Custom Locations as Platform Defaults

The Arc/HCI control plane gives every VM a consistent set of
capabilities, and the platform enables them by default rather than
leaving them as opt-in:

- **Arc connection** for the VM and its host.
- **Azure Monitor Agent and Data Collection Rules** for logs and
  performance counters.
- **Azure Update Manager** for patching.
- **Guest Configuration / Machine Configuration** for compliance
  audits.
- **Defender for Servers** where licensing applies.

Custom locations are referenced **by name** rather than by GUID, and
resolved through a shared lookup. Rebuilding a custom location or
moving a cluster does not require rewriting every module call:

```hcl
data "azapi_resource" "custom_location" {
  type      = "Microsoft.ExtendedLocation/customLocations@2021-08-15"
  name      = var.custom_location_name   # e.g. "cl-dcX-azl-cl01"
  parent_id = data.azurerm_resource_group.cluster.id
}
```

---

## 10. Policy and Compliance

A policies module turns the standard Azure pattern (initiative →
assignment → parameter set → exemptions) into a few lines per
environment. Production carries a stricter overlay than test, and new
clusters inherit the same baseline automatically.

```hcl
module "baseline_policies_prod" {
  source        = "./modules/policies/assignments"
  scope_id      = data.azurerm_resource_group.cluster.id
  initiative_id = local.initiatives.azure_local_baseline
  parameters    = local.policy_params.prod
  enforce       = true
}
```

---

## 11. CI/CD With Appropriate Guardrails

Every PR runs:

- `terraform fmt -recursive` and `terraform validate`.
- `tflint` with custom rules for the naming conventions.
- A super-linter pass for YAML, Markdown, and shell.
- Security scanning (secret detection and IaC scanning).
- A plan against the affected environment, posted as a PR comment.

Production environments are gated: locked state, required reviewers,
no auto-apply, and resource locks on critical infrastructure. Test and
lab environments are intentionally faster, since that is where
engineers experiment.

---

## 12. Repository-Aware Automation

A set of GitHub Actions workflows keeps the repository in sync with
the live platform:

- When a logical network issue is closed, the workflow queries Azure
  for current lnets, sorts them by datacenter → environment → CIDR,
  and rewrites the dropdowns in every server-request issue template.
- It refreshes available **VM images**, **maintenance windows**, and
  **custom locations** on a schedule.
- It opens a draft PR with the changes so the updates are reviewed
  rather than merged silently.
- A "TF Builder" workflow watches issue creation and turns a completed
  request form into a Terraform file in the right cluster and
  environment folder, already named, tagged, and module-wired.

The intent is that the issue templates a developer fills out today
reflect what actually exists on the platform today, rather than what
existed when the templates were last hand-edited.

---

## 13. Developer Self-Service via Issue Templates

Application teams do not open tickets in another system, and they do
not write Terraform. They open a GitHub issue using a structured form:

- **Windows server request**
- **Linux server request**
- **SQL server request**
- **Logical network request**
- **AKS cluster request**
- **Image build request**

Each form validates required fields (environment, datacenter, OS,
sizing, network, maintenance window, owning team) and pulls live
dropdowns from the platform. On submit:

1. Labels and metadata classify the request.
2. The TF Builder workflow generates the corresponding Terraform.
3. A draft PR is opened, linked to the issue.
4. Reviewers approve; CI plans and applies.
5. On close, the bot refreshes templates so the new resource is
   selectable for the next request.

The loop is closed: requesters never touch Terraform, engineers
review small generated diffs, and the platform remains the source of
truth.

---

## 14. Where AI Helps, and Where It Does Not

A repository-scoped Copilot agent and a small set of on-demand skills
(VM builder, lnet builder, ASR onboarding, maintenance window
advisor, inventory explorer) help engineers draft compliant Terraform
without re-reading the standards every time. The agent defaults to
non-production, asks before touching production, and follows the same
naming, tagging, and module conventions a human reviewer would
enforce. It is treated as an aid for drafting and exploration, not as
an authority — the change still goes through pull request review like
any other.

---

## Summary

1. **AVMs are the starting point, not the destination.** Plan to fork
   them, and at scale plan for a private Terraform registry to
   distribute the forks.
2. **`azapi`, not `azurerm`.** Azure Local is its own resource
   provider and the API moves faster than the providers do.
3. **Everything in Terraform.** Including DR, patching, policy, and
   tags.
4. **YAML for humans, HCL for machines.** Make intent easy to
   express; make correctness automatic.
5. **Convention over configuration.** Names and tags carry meaning so
   automation can act on them.
6. **Day-0 agents are part of the VM definition.** Extensions,
   maintenance window assignment, and the `ansible-managed` tag all
   apply at provisioning time.
7. **Self-service through structured issues.** Forms in, pull
   requests out.
8. **Repository automation maintains the catalog.** Dropdowns and
   templates are generated from the live platform, not edited by
   hand.
9. **Production is gated, test is fast.** Both are deliberate.
10. **Review the diff.** Everything is reviewable because everything
    is code.
