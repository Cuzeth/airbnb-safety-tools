# Important Information

This is an informational notice that accompanies SafeStay. The legally
operative terms of use are in [LICENSE](./LICENSE) (MIT). The text below
expands on the warranty, liability, and usage posture of the project; it is
not a separate contract or end-user license agreement.

## No warranty (per the MIT license)

The MIT License under which SafeStay is distributed already states that the
software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND. That includes
warranties of merchantability, fitness for a particular purpose, accuracy,
completeness, security, and non-infringement. False negatives (real cameras
not flagged) and false positives (innocent devices flagged) are expected,
frequent, and unavoidable.

**Do not rely on this tool as the sole basis for any decision about your
safety.**

## No liability (per the MIT license)

The MIT License states that the authors and copyright holders are not liable
for any claim, damages, or other liability arising from the software. To the
maximum extent permitted by applicable law, that includes:

- Personal injury, emotional distress, or property damage
- Financial loss, including refunds, cancellations, or bookings
- Account termination, blacklisting, or suspension by any platform (Airbnb,
  Vrbo, Booking.com, hotel chains, internet service providers, etc.)
- Civil claims or criminal charges brought by hosts, network operators,
  platforms, or government entities
- Damage to networks, devices, or services arising from scanning activity
- Any other harm, loss, expense, or liability of any nature

Use the software at your own risk.

## No endorsement, no encouragement, no recommendation

The author does not condone, encourage, endorse, recommend, instruct, or
advise the use of this software against any network, system, device, host,
platform, or person. Examples, scenarios, walkthroughs, port lists, OUI
databases, and detection signatures are provided for educational and
informational purposes only; they describe what the tool can technically do,
not how anyone should use it.

## Not legal advice

Nothing in this software, its documentation, its source code, its output, or
any associated material constitutes legal advice. That includes the in-app
"If You Found Something" guide, the HTML and JSON reports, the README, this
notice, and any link to any external resource.

Laws governing privacy, surveillance, network access, port scanning,
recording, and short-term rental hosts differ enormously by country, state,
province, and city — and they change. The legal status of running this
tool, the legal status of a host operating a camera, and the legal remedies
available to you all depend on facts and jurisdictions only you and a
qualified attorney can assess.

If you believe a crime has been committed, contact local law enforcement and
consult a licensed attorney in your jurisdiction. Do not rely on this
software, its author, or any guidance bundled with it as a substitute for
professional legal advice.

## Authorization is your responsibility

Network scanning, port scanning, and active probing of devices may be
illegal, regulated, or restricted under:

- Computer-misuse, anti-hacking, or unauthorized-access laws (e.g. the
  United States Computer Fraud and Abuse Act, the United Kingdom Computer
  Misuse Act, the EU NIS2 Directive, and equivalents elsewhere)
- Wiretap, surveillance, and privacy statutes
- The terms of service of the network you are connected to (hotel WiFi,
  Airbnb host WiFi, public hotspots, cellular hotspots, employer networks,
  etc.)
- The terms of service of any platform you intend to file a report with
- Local rental, hospitality, and consumer-protection regulations

You alone are responsible for confirming, before you run this tool, that you
have lawful authorization to scan the network you are connected to and to
probe every device on it. The author provides no list of which networks are
"safe to scan" — there is no such list, and the answer depends on your
jurisdiction and the specific network.

## Data handling

SafeStay performs all scanning locally. It does not transmit scan results to
any server, and it does not contact any third-party host during normal
operation. Local IP detection is done by enumerating network interfaces; no
DNS resolver or remote address is contacted for that purpose.

When you press `e`, SafeStay writes a report to your working directory in
two formats:

- An HTML file (human-readable)
- A JSON file (machine-readable, same data)

Both files contain the IP address, MAC address, vendor label (from a local
OUI database), open ports, and risk reasons for every device discovered on
the local subnet, plus a timestamp and the subnet identifier.

MAC and IP addresses associated with identifiable people or premises may
constitute personal data under your jurisdiction's data-protection laws
(for example, GDPR in the EU/UK, CCPA/CPRA in California, LGPD in Brazil).
If that is the case, you — not the author of SafeStay — are the data
controller for any report you generate, retain, or share. Consider
redacting MAC addresses before sharing reports with third parties, and
delete reports when you no longer need them.

SafeStay does not include any analytics, telemetry, update-check, or
crash-reporting mechanism.

## No affiliation

SafeStay is not affiliated with, endorsed by, sponsored by, or connected to
Airbnb, Inc., Vrbo, Booking Holdings, any hotel chain, any camera
manufacturer, any chip manufacturer, any standards body, any government
agency, or any other organization or product named in this software or its
documentation. Trademarks belong to their respective owners and are
referenced solely for identification.

Mentioning a vendor name (e.g. Hikvision, Dahua, Wyze, Ring, Tuya) in a
detection rule, port description, or example output is not an accusation
against that vendor, a claim about that vendor's products, or a
recommendation about that vendor. It is a technical reference to a
publicly-documented protocol, MAC OUI assignment, or product line.

## "Use at your own risk" is not a metaphor

If, after reading this notice, you have any doubt about whether you should
run this software in a given situation, do not run it. Personal-safety
decisions, decisions about whether to contact law enforcement, and decisions
about engaging legal counsel are yours alone, based on your jurisdiction and
circumstances. The author cannot help you with those decisions and accepts
no responsibility for them.
