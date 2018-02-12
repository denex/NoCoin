"""
    Script generate rules for LittleSnitch firewall based on blacklist.txt
    Usage:
        python create_little_snitch_rules.py | pbcopy
    And then paste into LittleSnitch configuration
"""
from __future__ import division, print_function
import os
import re

LittleSnitchRuleTemplate = """action: deny
direction: outgoing
priority: regular
process: any
owner: me
destination: domain {domain}
port: any
protocol: any
notes: {notes}
"""


def deduplicate(domains):
    """
    Remove lower domains, eg: 'load.jsecoin.com' idf 'jsecoin.com' exists
    :type domains: iterable
    :rtype: set(str)
    """
    domains = list(domains)  # mutable copy
    result = set()
    while domains:
        dom = domains.pop()
        for other in domains:
            if dom.endswith('.' + other):
                # Found some upper level domain in 'other'
                break
        else:
            result.add(dom)
    return result


def main(blacklist_filename):
    with open(blacklist_filename) as f:
        domains = set(d for d in
                      (re.sub('^\*\.?', '', l.strip().partition('//')[-1].partition('/')[0]) for l in f)
                      if d)
    for domain in sorted(deduplicate(domains)):
        print(LittleSnitchRuleTemplate.format(domain=domain, notes="NoCoin rule for %s domain" % domain))


if __name__ == '__main__':
    main(os.path.join("src", "blacklist.txt"))
