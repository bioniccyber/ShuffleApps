# shuffle-dig-domain
A Shuffle SOAR app built on Bionic's mass-dig script. Shuffle is an open source security orchestration, automation, and response (SOAR) platform built by [frikky](https://github.com/frikky). It has thousands of premade integrations and uses open frameworks like OpenAPI to ease migration. The workflow editor is based on a no-code thought process to empower non-developer, and the app creator makes you able to inegrate any platform in minutes. 

The mass-dig script ("dig_domain_to_ip.py") has two main functions:

single_domain_to_ip:
 - Expects a single domain and outputs to screen. Useful for testing purposes.
 
bulk_domain_to_ip:
 - Expects a filename containing domains and outputs to a timestamped file.
