:local resolve do={
	########################################## Enter URL's Here
	:local weburl [:toarray value="eu.wifiportal.io, bbc.co.uk,itv.co.uk,movenpick.com,galaxy.execloud.net,mbr.co.uk,live.com,microsoft.com,airangel.com,apple.com,samsung.com,bmw.com,ford.com,sony.com,facebook.com,twitter.com,instagram.com"];
	########################################## Enter URL's Here
	:local result {""};
	:local retry 0;
	:set retry 0;
	:if ($flush=true) do={
		:put [/ip dns cache flush];
	};
	:put "###### Test #$i. Testing with $svr ######";
	:local startTime [/system clock get time];
	:put "Start time: $startTime";
	:foreach element in=$weburl do={
		:put "Trying $element";
		:if ($remoteSrv=true) do={
				:do {:set result [resolve $element server $svr];} on-error={  
					:put "###### DNS Timeout.... Trying once more before aborting test"; :do {
					:set result [resolve $element server $svr];
					:set retry ($retry + 1);
				};
			};
		} else={
			:do {:set result [resolve $element];} on-error={  
					:put "###### DNS Timeout.... Trying once more before aborting test"; :do {
					:set result [resolve $element];
					:set retry ($retry + 1);
				};
			};
		};
	:put "Success $result";
	};
	##################################### Local Resolver
	#################################### Format Results
	##################################### Time formatting
	:local sum 0;
	:local endTime [/system clock get time];
	:local finalTime ( $endTime - $startTime );
	:set sum ( $sum + ( [ :pick $finalTime 0 2 ] * 60 * 60 ));
	:set sum ( $sum + ( [ :pick $finalTime 3 5 ] * 60 ));
	:set sum ( $sum + [ :pick $finalTime 6 8 ] );
	#################################### Time formatting
	:put "End time: $endTime";
	:local overRun 0;
	:set overRun ($sum - 1);
	:local underRun 0;
	:set underRun (1 - $sum);
	if ($sum <= 1) do={
		:local result "###### Test #$i OO-PASSED: Retries = $retry, Resolved $thisMany URL's in $sum seconds using $test.";
		:set ($results->i) $result;
	};
	if ($sum > 1) do={
		:local result "###### Test #$i XX-FAILED: Retries = $retry, Resolved $thisMany URL's in $sum seconds using $test. That is $overRun more than it should be.";
		set ($results->i) $result;
	};
	:return $reults;
	#################################### Format Results
};
###################################### Resolver

###################################### Define Servers and Test
:put "###### Getting remote DNS servers for performance testing ######";
:local results {""};
:local manDnsServers [/ ip dns get servers];
:local dynDnsServers [/ ip dns get dynamic-servers];
:local dnsServers ($manDnsServers , $dynDnsServers , "the local server, un-cached" , "the local server, cached");
:local i 0; 
:local flush true;
:local remoteSrv false;
:local thisMany [:len $weburl];
:local length [:len $dnsServers];
#Distinguishes local DNS as Mikrotik
:local localTests ($length - 2); 
#Distinguishes local DNS as Mikrotik
:foreach svr in=$dnsServers do={
	:local position (:put [:find $dnsServers $svr]);
	:set flush true;
	:set remoteSrv false;
	if ($position = $length -1) do={
		:set flush false;
	};
	:if ($position < $localTests) do={
		:set remoteSrv true;
	};
	:set i ($i + 1);
	:put [$resolve svr=$svr results=$results i=$i flag=$flag flush=$flush remoteSrv=$remoteSrv];
};
###################################### Define Servers and Test
###################################### Print Final Results
:put "#############################################";
:put "Each test should take <1s in a healthy system.";
:put "There should be 0 retries.";
:put "#############################################";
:foreach i in=$results do={
	:put $i;
};
###################################### Print Final Results


