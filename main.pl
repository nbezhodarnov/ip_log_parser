sub extract_ip {
	my ($line) = @_;
	if ($line =~ /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {
		return $1;
	}
	return "";
}

sub check_rule_1 {
	my ($line) = @_;
	if ($line =~ /(Macintosh)|(Intel)|((Windows NT 5.1)(.*)(rv:))/) {
		return 1;
	}
	return 0;
}

sub check_rule_2 {
	my ($line) = @_;
	if ($line =~ /(HTTP\/1.1)(.*)(WEBDAV|MSIE 8.0|Telesphoreo)/) {
		return 1;
	}
	return 0;
}

sub check_rule_3 {
	my ($line) = @_;
	if ($line =~ /(GET|POST|HEAD|PROPFIND|OPTIONS)(.*)(499 0 "-")/) {
		return 1;
	}
	return 0;
}

sub check_rule_4 {
	my ($line) = @_;
	if ($line =~ /Python-urllib/) {
		return 1;
	}
	return 0;
}

sub check_rule_5 {
	my ($line) = @_;
	if ($line =~ /(\\x[0-9A-Z][0-9A-Z]){2,}/) {
		return 1;
	}
	return 0;
}

sub generate_ip_counts_table {
	my %ip_counts_table = ();
	my @lines = @_;
	for my $line (@lines) {
		my $ip = extract_ip($line);
		if ($ip == "") {
			continue;
		}
		if (exists($ip_counts_table{$ip})) {
			$ip_counts_table{$ip} += 1;
		} else {
			$ip_counts_table{$ip} = 1;
		}
	}
	return %ip_counts_table;
}

sub get_top_10_ip_list_from_table {
	my (%ip_counts_table) = @_;
	my @top_10_ip_list = sort { $ip_counts_table{$b} <=> $ip_counts_table{$a} } keys %ip_counts_table;
	if ($#top_10_ip_list > 9) {
		$#top_10_ip_list = 9;
	}
	return @top_10_ip_list;
}

sub generate_top_10_ip_list {
	my @lines = @_;
	my %ip_counts_table = generate_ip_counts_table(@lines);
	return get_top_10_ip_list_from_table(%ip_counts_table);
}

sub print_suspicious_requests {
	my @lines = @_;
	for my $line (@lines) {
		my $suspicious_things_count = 0;
		$suspicious_things_count += check_rule_1($line);
		$suspicious_things_count += check_rule_2($line);
		$suspicious_things_count += check_rule_3($line);
		$suspicious_things_count += check_rule_4($line);
		$suspicious_things_count += check_rule_5($line);
		if ($suspicious_things_count >= 2) {
			print $line;
		}
	}
}

my $arguments_number = $#ARGV + 1;
if ($arguments_number != 1) {
	die("You must provide filepath!\n");
}
my $input_log = $ARGV[0];

open(my $in, "<", $input_log) or die "Can't open file: $!\n";

my @lines = <$in>;
my @top_10_ip_list = generate_top_10_ip_list(@lines);
print "Top 10 IP:\n";
print join("\n", @top_10_ip_list), "\n\n";
print "Suspicious requests:\n";
print_suspicious_requests(@lines);
