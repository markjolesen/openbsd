#!/usr/bin/perl
#
# License CC0 PUBLIC DOMAIN
#
# To the extent possible under law, Mark J. Olesen has waived all copyright 
# and related or neighboring rights to mk.pl file. This work is published 
# from: United States.
#

my $CFLAGS = "-DLIBRESSL_INTERNAL -DOPENSSL_NO_ASM"
	    ." -I."
	    ." -I./arch/i386"
	    ." -I./engine -I./buffer -I./objects"
	    ." -I./aes -I./dh -I./lhash -I./dsa -I./rsa -I./sha"
	    ." -I./asn1 -I./des -I./bn -I./ec -I./evp"
	    ." -I./x509v3 -I./x509 -I./pkcs12"
	    ." -I./ecdsa -I./modes";

#            ." -I../libc/include"

sub slurp_dir 
{
	my $dir = shift;
	my $dh;
	my @list;
	opendir ($dh, $dir);
	while ($file = readdir ($dh)) 
	{
		next if (($file eq '.') || ($file eq '..'));
		if (-d "$dir/$file") 
		{
			my @a= slurp_dir("$dir/$file");
			if (scalar(@a))
			{
				push(@list, \@a);
			}
		}
		elsif ($file =~ /\.c$/) 
		{
			push(@list, "$dir/$file");
		}
	}
	closedir($dh);

	return @list;
}

sub print_objs
{
	my ($tag, @files) = @_;
	my @objs;
	my @tags;

	push(@tags, $tag);

	foreach my $file (@files)
	{
		if (ref $file ne 'ARRAY')
		{
			my $o= $file;
			if ($o =~ s/^\.//)
			{
				$o = substr($o, 1);
			}
			if ($o =~ s/^\///)
			{
				$o = substr($o, 1);
			}
			my ($p, $f) = $o =~ m{(.+)/([^/]+)$};
			if ($f eq '')
			{
				$f= $o;
			}
			push(@objs, $f);
		}
		else
		{
			my $o= $file->[0];
			if (ref $o ne 'ARRAY')
			{
				if ($o =~ s/^\.//)
				{
					$o = substr($o, 1);
				}
				if ($o =~ s/^\///)
				{
					$o = substr($o, 1);
				}
				if ($o ne '')
				{
					my ($p, $f) = $o =~ m{(.+)/([^/]+)$};
					$p= uc($p).'_OBJS';
					my @a= print_objs($p, @$file);
					push(@tags, @a);
				}
			}
		}
	}

	print "\n$tag=&\n";

	my $slot= 0;
	my $slots= scalar(@objs);
	foreach my $obj (@objs)
	{
		$slot++;
		$obj =~ s{\.[^.]+$}{}; 
		print FHLBC "-+obj/$obj.obj\n";
		print "\t\$(OBJ)\\$obj.obj";
		if ($slots > $slot)
		{
			print ' &';
		}
		print "\n";
	}

	return @tags;
}

sub print_rule
{
	my $file= shift;
	my $cmd= "g++ -MM $CFLAGS -c $file | "
		.'sed -re "s/(.*)\.o/$\(OBJ\)\/\1.obj/"';
	my $dep= `$cmd`;
	$dep =~ tr{\\}{&};
	$dep =~ tr{/}{\\};
	print $dep;
	print "\t".'*$(CC) $(CFLAGS) -fo=$@ $[@'."\n\n";
}

sub print_rules
{
	my @files = @_;

	foreach my $file (@files)
	{
		if (ref $file ne 'ARRAY')
		{
			print_rule($file);
		}
		else
		{
			my $o= $file->[0];
			if (ref $o ne 'ARRAY')
			{
				if ($o =~ s/^\.//)
				{
					$o = substr($o, 1);
				}
				if ($o =~ s/^\///)
				{
					$o = substr($o, 1);
				}
				if ($o ne '')
				{
					print_rules(@$file);
				}
			}
		}
	}
}

sub print_tgt
{
	my @objs = @_;

	print "\nLIB_OBJS=&\n";

	my $slot= 0;
	my $slots= scalar(@objs);
	foreach my $obj (@objs)
	{
		$slot++;
		print "\t\$($obj)";
		if ($slots > $slot)
		{
			print ' &';
		}
		print "\n";
	}

	print <<'END'

all : $(LIB)\openssl.lib .SYMBOLIC

$(LIB)\openssl.lib : $(LIB_OBJS)
	wlib -n $^@ @ow32d.lbc

$(OBJ) :
	mkdir $(OBJ)

$(LIB) :
	mkdir $(LIB)

END



}

print <<'END';
#
# License CC0 PUBLIC DOMAIN
#
# To the extent possible under law, Mark J. Olesen has waived all copyright 
# and related or neighboring rights to owd32.mak file. This work is published 
# from: United States.
#

OBJ=obj
LIB=..\lib

DEFINES= -DLIBRESSL_INTERNAL -DOPENSSL_NO_ASM

INCLUDES= -i. 
INCLUDES+= -i.\arch\i386 
INCLUDES+= -i.\engine -i.\buffer -i.\objects 
INCLUDES+= -i.\aes -i.\dh -i.\lhash -i.\dsa -i.\rsa -i.\sha 
INCLUDES+= -i.\asn1 -i.\des -i.\bn -i.\ec -i.\evp 
INCLUDES+= -i.\x509v3 -i.\x509 -i.\pkcs12 
INCLUDES+= -i.\ecdsa -i.\modes

CC=wcc386
CFLAGS=-3r -mf -bt=DOS $(DEFINES) $(INCLUDES)

END

my @files= slurp_dir(".");
open(FHLBC, '>', 'owd32.lbc');
my @objs= print_objs('CRYPTO_OBJS', @files);
close(FHLBC);

print_tgt(@objs);
print_rules(@files);

