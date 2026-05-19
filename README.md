# Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide InSpec Profile

The Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide (STIG) InSpec Profile can help programs automate their compliance checks of Ubuntu 22.04 LTS systems against Department of Defense (DoD) requirements.

- Profile Version: `1.0.0`
- Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide V2R8

This profile was developed to reduce the time it takes to perform security checks based upon the STIG guidance from the Defense Information Systems Agency (DISA) in partnership between the DISA Services Directorate (SD) and the DISA Risk Management Executive (RME) office.

The results of a profile run will provide information needed to support an Authority to Operate (ATO) decision for the applicable technology.

The Ubuntu 22.04 LTS STIG Profile uses the [InSpec](https://github.com/inspec/inspec) open-source compliance validation language to support automation of the required compliance, security and policy testing for Assessment and Authorization (A&A) and Authority to Operate (ATO) decisions and Continuous Authority to Operate (cATO) processes.

Table of Contents
=================

* [Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide InSpec Profile](#canonical-ubuntu-2204-lts-security-technical-implementation-guide-inspec-profile)
   * [Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide (Ubuntu 22.04 STIG)](#canonical-ubuntu-2204-lts-security-technical-implementation-guide-ubuntu-2204-stig)
* [Getting Started and Intended Usage](#getting-started-and-intended-usage)
   * [Intended Usage - main vs releases](#intended-usage---main-vs-releases)
   * [Environment Aware Testing](#environment-aware-testing)
   * [Tailoring to Your Environment](#tailoring-to-your-environment)
* [Running the Profile](#running-the-profile)
   * [(connected) Running the Profile Directly](#connected-running-the-profile-directly)
   * [(disconnected) Running the profile from a local archive copy](#disconnected-running-the-profile-from-a-local-archive-copy)
   * [Different Run Options](#different-run-options)
* [Using Heimdall for Viewing Test Results and Exporting for Checklist and eMASS](#using-heimdall-for-viewing-test-results-and-exporting-for-checklist-and-emass)

## Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide (Ubuntu 22.04 STIG)

The DISA RME and DISA SD Office, along with their vendor partners, create and maintain a set of Security Technical Implementation Guides for applications, computer systems and networks connected to the Department of Defense (DoD). These guidelines are the primary security standards used by the DoD agencies. In addition to defining security guidelines, the STIGs also stipulate how security training should proceed and when security checks should occur. Organizations must stay compliant with these guidelines or they risk having their access to the DoD terminated.

The Ubuntu 22.04 LTS STIG (see public.cyber.mil/stigs/) offers a comprehensive compliance guide for the configuration and operation of your Canonical Ubuntu 22.04 LTS system.

The requirements associated with the Ubuntu 22.04 LTS STIG are derived from the [Security Requirements Guides](https://csrc.nist.gov/glossary/term/security_requirements_guide) and align to the [National Institute of Standards and Technology](https://www.nist.gov/) (NIST) [Special Publication (SP) 800-53](https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/800-53) Security Controls, [DoD Control Correlation Identifier](https://public.cyber.mil/stigs/cci/) and related standards.

The Ubuntu 22.04 LTS STIG profile checks were developed to provide technical implementation validation to the defined DoD requirements. The guidance can provide insight for any organizations wishing to enhance their security posture and can be tailored easily for use in your organization.

### Source Guidance

- Canonical Ubuntu 22.04 LTS Security Technical Implementation Guide V2R8

### Current Profile Statistics

The profile will be tested on every commit and every release against both `vanilla` and `hardened` images using a CI/CD pipeline. The `vanilla` images are unmodified base Ubuntu 22.04 images. The `hardened` images have had their settings configured for security according to STIG guidance. Testing both vanilla and hardened configurations of both containerized and virtual machine implementations of Ubuntu 22.04 LTS is necessary to ensure the profile works in multiple environments.

# Getting Started and Intended Usage

1. It is intended and recommended that InSpec and the profile be run from a **"runner"** host, either from source or a local archive — [Running the Profile](#running-the-profile) — (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target [remotely over **ssh**].

2. **For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.**

3. The latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

4. Always use the latest version of the `released profile` (see below) on your system.

## Intended Usage - `main` vs `releases`

1. The latest `released` version of the profile is intended for use in A&A testing, as well as providing formal results to Authorizing Officials and IAMs. Please use the `released` versions of the profile in these types of workflows.

2. The `main` branch is a development branch that will become the next release of the profile. The `main` branch is intended for use in _developing and testing_ merge requests for the next release of the profile, and _is not intended_ to be used for formal and ongoing testing on systems.

## Environment Aware Testing

The Ubuntu 22.04 LTS STIG profile is `container aware` and is able to determine when the profile is being executed inside or outside a `docker container` and will only run the tests that are appropriate for the environment it is testing in. The tests are tagged as `host`, `host, container`, or `container-conditional`.

All the profile's tests (`controls`) apply to the `host`, but many of the controls are `Not Applicable` when running inside a `docker container` (such as controls that test auditd, systemd services, or kernel parameters). When running inside a `docker container`, tests that are only applicable to the host will be marked as `Not Applicable` automatically via `only_if` guards that check `virtualization.system.eql?('docker')`.

Controls tagged `container-conditional` (such as SSH-related controls) will still run inside a container if the relevant service or package is present.

## Tailoring to Your Environment

### Profile Inputs (see `inspec.yml` file)

This profile uses InSpec Inputs to make the tests more flexible. You are able to provide inputs at runtime either via the CLI or via YAML files to help the profile work best in your deployment.

#### **_Do not change the inputs in the `inspec.yml` file_**

The `inputs` configured in the `inspec.yml` file are **profile definition and defaults for the profile** and not for the user. InSpec provides two ways to adjust the profile's inputs at run-time that do not require modifying `inspec.yml` itself.

To tailor the tested values for your deployment or organizationally defined values, **_you may update the inputs_**.

#### Update Profile Inputs from the CLI or Local File

1. Via the CLI with the `--input` flag
2. Pass them in a YAML file with the `--input-file` flag.

More information about InSpec inputs can be found in the [InSpec Inputs Documentation](https://docs.chef.io/inspec/inputs/).

#### Key Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `sudoers_config_files` | Paths to sudoers configuration files | `['/etc/sudoers', '/etc/sudoers.d/*']` |
| `passwordless_admins` | Admin groups permitted NOPASSWD in sudoers | `[]` |
| `sshd_config_values` | Expected SSH daemon configuration values | See `inspec.yml` |
| `allow_container_openssh_server` | Allow OpenSSH server in containers | `false` |
| `audit_rule_keynames` | Expected audit rule key names by path/syscall | See `inspec.yml` |
| `audit_rule_keynames_overrides` | Overrides for specific audit rule key names | See `inspec.yml` |
| `disable_slow_controls` | Skip controls with long run times | `false` |

See the `inspec.yml` file for the complete list of available inputs and their default values.

# Running the Profile

## (connected) Running the Profile Directly

Against a remote host over SSH:

```bash
inspec exec https://github.com/chaddowen59-coder/canonical-ubuntu-22.04-lts-stig-baseline/archive/main.tar.gz \
  --input-file=<your_inputs_file.yml> \
  -t ssh://<hostname>:<port> \
  --sudo \
  --reporter=cli json:<your_results_file.json>
```

Against a local Docker container:

```bash
inspec exec https://github.com/chaddowen59-coder/canonical-ubuntu-22.04-lts-stig-baseline/archive/main.tar.gz \
  --input-file=<your_inputs_file.yml> \
  -t docker://<container_id> \
  --reporter=cli json:<your_results_file.json>
```

## (disconnected) Running the profile from a local archive copy

If your runner is not always expected to have direct access to the profile's hosted location, use the following steps to create an archive bundle of this profile and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the **"runner"** host uses this profile for the first time, follow these steps:

```bash
mkdir profiles
cd profiles
git clone https://github.com/chaddowen59-coder/canonical-ubuntu-22.04-lts-stig-baseline.git
inspec archive canonical-ubuntu-22.04-lts-stig-baseline
# transfer archive to air-gapped runner
inspec exec <name of generated archive> \
  --input-file=<your_inputs_file.yml> \
  -t ssh://<hostname>:<port> \
  --sudo \
  --reporter=cli json:<your_results_file.json>
```

For every successive run, follow these steps to always have the latest version of this profile:

```bash
cd canonical-ubuntu-22.04-lts-stig-baseline
git pull
cd ..
inspec archive canonical-ubuntu-22.04-lts-stig-baseline
```

## Running Against a Container Image (Disconnected)

```bash
inspec exec ubuntu2204.tar.gz \
  --input-file=profile-inputs.yaml \
  -t docker://<container_id> \
  --reporter=cli json:<your_results_file.json>
```

## Different Run Options

[Full exec options](https://docs.chef.io/inspec/cli/#options-3)

# Using Heimdall for Viewing Test Results and Exporting for Checklist and eMASS

The JSON results output file can be loaded into **[Heimdall](https://heimdall-lite.mitre.org/)** for a user-interactive, graphical view of the profile scan results. Heimdall-Lite is a `browser only` viewer that allows you to easily view your results directly and locally rendered in your browser.

It can also **_export your results into a DISA Checklist (CKL) file_** for easy upload into eMASS using the `Heimdall Export` function.

Depending on your environment, you can also use the [SAF CLI](https://saf-cli.mitre.org) to run a local docker instance of Heimdall-Lite via the `saf view:heimdall` command.

The JSON results file may also be loaded into a **[full Heimdall Server](https://github.com/mitre/heimdall2)**, allowing for additional functionality such as storing and comparing multiple profile runs.

# Authors

Defense Information Systems Agency (DISA) https://www.disa.mil/

STIG support by DISA Risk Management Team and Cyber Exchange https://public.cyber.mil/

MITRE Security Automation Framework Team https://saf.mitre.org

### NOTICE

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx
