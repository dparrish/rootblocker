# rootblocker

Block IPs that continuously fail root SSH attempts.

This tool tails logs in Elasticsearch looking for "Failed password for root" messages. When enough attempts are made in a period it adds the IP to a block list on a router.

Currently the only router supported is the Ubiquiti EdgeRouter, because that's what I use.
