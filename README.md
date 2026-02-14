# Windows Security Log Analyzer

Windows Security Log Analyzer is a focused helper for SOC analysts and
defenders. It is designed to:

- Pull the most relevant Windows Security events from the local machine or a
  crafted incident file
- Present them in a clear, colored terminal view and export them to CSV

The tool supports both **live collection** from the local Windows Security
log and an **offline demo mode** that loads a realistic XML incident.

---

**Features**

- Live collection from the Windows Security event log using native APIs
  (`pywin32` / `win32evtlog`)
- Opinionated focus on important security event IDs by default
- Colored terminal UI using `colorama` and `rich`
- CSV export for filtered, normalized events
- Demo mode backed by XML incidents for training and testing

---

## Project structure

The repository is intentionally small and easy to navigate:

- `app.py` – main CLI entry point and argument parsing
- `models.py` – data models, event rules, time and ID parsing helpers
- `sources.py` – live Windows Security log and demo XML loaders
- `presentation.py` – terminal rendering and CSV export
- `demo/`
  - `demo_incident.xml` – sample incidents with suspicious activity
  - `demo.csv` – generated when you run the tool in `--demo` mode
- `requirements.txt` – Python dependencies

---

## Installation

1. Make sure you are on **Windows** and have Python 3.9+ installed.
2. Clone or download this repository.
3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

Dependencies:

- `colorama` – safe, cross-platform colored output
- `rich` – modern terminal rendering and tables
- `pywin32` – access to the Windows Event Log API (`win32evtlog`)

---

## Usage

You can either run the tool directly from the source tree, or install the
published package and use the `winsecan` command.

### Installed CLI (`winsecan`)

After installing from PyPI:

```bash
pip install winsecan
```

Run against the local Windows Security log:

```bash
winsecan
```

This will:

- Query the `Security` log
- Retrieve up to 500 recent events
- Filter to important security event IDs
- Render them in a colored vertical view

Some common options:

```bash
# Show help
winsecan --help

# Increase the number of collected events
winsecan --max-events 1000

# Show all events instead of only important ones
winsecan --all-events

# Only include specific event IDs
winsecan --event-ids 4624,4625,4688

# Only include specific event levels
winsecan --levels warning,error,critical

# Export to CSV in addition to the terminal view
winsecan --csv-output security_events.csv

# Disable the rich UI and only export CSV
winsecan --no-ui --csv-output security_events.csv

# Hide noisy Local System logons (4624 / S-1-5-18)
winsecan --hide-system-logons

# Practice on the built-in demo incident
winsecan --demo
```

### Running from source (`python app.py`)

Change into the project directory:

```bash
cd windows-security-log-analyzer
```

#### Live mode (real Windows Security log)

Live mode queries the local Windows Security event log via `win32evtlog`
from `pywin32`. This usually requires an elevated terminal (Run as
Administrator).

Basic usage:

```bash
python app.py
```

This will:

- Query the `Security` log
- Retrieve up to 500 recent events
- Filter to important security events (see event list below)
- Render them in a colored vertical view

Useful options:

```bash
# Show help
python app.py --help

# Increase the number of collected events
python app.py --max-events 1000

# Show all events instead of only important ones
python app.py --all-events

# Only include specific event IDs
python app.py --event-ids 4624,4625,4688

# Only include specific event levels
python app.py --levels warning,error,critical

# Export to CSV in addition to the terminal view
python app.py --csv-output security_events.csv

# Disable the rich UI and only export CSV
python app.py --no-ui --csv-output security_events.csv

# Hide noisy Local System logons (4624 / S-1-5-18)
python app.py --hide-system-logons
```

#### Demo mode (offline training with XML incidents)

Demo mode does not touch the real Windows event log. It loads a static
XML file that describes several related security incidents:

- Incident 1: external RDP brute-force leading to domain admin backdoor.
- Incident 2: phished workstation user doing internal recon and lateral movement.
- Incident 3: administrator cleanup (disabling, removing, deleting the backdoor).

Run demo mode:

```bash
python app.py --demo
```

This will:

- Load events from `demo/demo_incident.xml`
- Render them in a colored table
- Export them by default to `demo/demo.csv`

You can override the CSV path:

```bash
python app.py --demo --csv-output my_demo.csv
```

Demo XML format:

- Root element: `<Events>`
- Child elements: `<Event>`
- Each `<Event>` contains:
  - `<TimeCreated>` – ISO 8601 timestamp (UTC)
  - `<Id>` – numeric event ID (e.g., 4625)
  - `<Level>` – severity string (e.g., Information, Warning)
  - `<Provider>` – source of the event
  - `<MachineName>` – hostname
  - `<Message>` – human-readable description

The file `demo/demo_incident.xml` is meant to feel like realistic
incidents you can walk through step by step, including attacker
activity and admin response.

---

## Important event IDs and what they mean

The analyzer ships with a predefined set of important event IDs
(`IMPORTANT_EVENT_IDS` in `models.py`). They are common signals for
authentication and privilege activity:

- **4624 – Logon success**
  - A user successfully signed in.
  - Useful to correlate with failures and to confirm account usage.

- **4625 – Logon failure**
  - Failed logon attempt (bad password, unknown user, etc.).
  - Useful for brute-force detection and password spraying.

- **4634 – Logoff**
  - A logon session ended.
  - Helps build timelines of user activity.

- **4672 – Special privileges assigned to new logon**
  - A privileged user (e.g., Administrator, Domain Admin) signed in.
  - Important for tracking high-privilege activity.

- **4688 – Process created**
  - New process started on the system.
  - Key for detecting suspicious tools and lateral movement.

- **4689 – Process exited**
  - A process terminated.
  - Useful for understanding process lifetimes and chains.

- **4720 – User account created**
  - A new user account was created.
  - Critical for detecting backdoor or temporary accounts.

- **4722 – User account enabled**
  - An account was re-enabled.
  - Suspicious when dormant or disabled accounts are reactivated.

- **4723, 4724 – Password change/reset attempts**
  - Password change or reset operations.
  - Important for account takeover investigations.

- **4725 – User account disabled**
  - An account was disabled.
  - Part of standard admin activity or attack cleanup.

- **4726 – User account deleted**
  - A user account was deleted.
  - Can be used to hide activity or clean up after intrusion.

- **4732, 4733 – Group membership changes**
  - Users added to or removed from security groups.
  - Critical for tracking lateral movement and privilege escalation.

- **4768, 4769, 4770, 4771 – Kerberos authentication**
  - Kerberos ticket requests and failures.
  - Useful for detecting Kerberos-based attacks (e.g., password spraying).

- **4798, 4799 – User enumeration**
  - A user’s local or group membership was enumerated.
  - Often seen when attackers explore what access they have.

Each of these IDs is mapped to a human-readable category in
`categorize_event` inside `models.py`.

---

## How the code is organized (high-level)

- `models.py`
  - `SecurityEvent` dataclass – normalized event object used everywhere.
  - `EVENT_RULES` and `IMPORTANT_EVENT_IDS` – central place for event categories.
  - `categorize_event`, `parse_time`, `parse_event_ids`, `normalize_level_name`, `parse_levels`.

- `sources.py`
  - `get_raw_events` – reads from the Windows Security event log via `win32evtlog`.
  - `normalize_event` – converts raw dictionaries into `SecurityEvent`.
  - `collect_events` – drives live collection and filtering for live mode.
  - `load_events_from_demo_xml`, `load_events_for_demo`, `resolve_demo_paths` – load events from `demo/demo_incident.xml`.

- `presentation.py`
  - `render_table` – uses `rich` to draw a colored table in the terminal.
  - `render_vertical` – shows each event as a panel with key/value pairs.
  - `export_to_csv` – writes events into a CSV file.
  - `color_for_event`, `truncate`, `export_events_if_requested`, `render_events_if_requested`.

- `app.py`
  - CLI entrypoint: parses arguments, decides between live and demo mode,
    and calls into `sources` and `presentation`.

---

## Running in different scenarios

- Quick view of important live events:

  ```bash
  python app.py
  ```

- Focus only on failed logons:

  ```bash
  python app.py --event-ids 4625
  ```

- Export all events to CSV without terminal UI:

  ```bash
  python app.py --all-events --no-ui --csv-output all_events.csv
  ```

- Practice on the demo incident:

  ```bash
  python app.py --demo
  ```

- Show only warning and higher severity events:

  ```bash
  python app.py --levels warning,error,critical
  ```
