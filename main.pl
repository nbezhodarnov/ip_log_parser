sub get_top_10_ip_list {
	my %ip_list = ();
	my $ip = "";
	for my $line (@_) {
		$ip = $line;
		if ($ip =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {
			$ip = $1;
		} else {
			continue;
		}
		if (exists($ip_list{$ip})) {
			$ip_list{$ip} = $ip_list{$ip} + 1;
		} else {
			$ip_list{$ip} = 1;
		}
	}
	
	my @top_10_ip_list = ($ip_list);
	foreach $ip(keys %ip_list) {
		my $i = 0;
		my $el = "";
		while (($i, $el) = each @top_10_ip_list) {
			if ($ip_list{$ip} > $ip_list{$el}) {
				break;
			}
		}
		if ($i <= 10) {
			splice (@top_10_ip_list, $i - 1, 0, $ip);
		}
		splice (@top_10_ip_list, 10);
	}
	return @top_10_ip_list;
}

open(my $in,  "<",  "access.log")  or die "Can't open access.log: $!";

my @top_10_ip = get_top_10_ip_list(<$in>);
print "Top 10 IP:\n";
print join("\n", @top_10_ip), "\n";
