:local checkDNS do={
	########################################## Enter URL's Here
	:local weburl [:toarray value="eu.wifiportal.io, bbc.co.uk,itv.co.uk,movenpick.com,galaxy.execloud.net,mbr.co.uk,live.com,microsoft.com,airangel.com,apple.com,samsung.com,bmw.com,ford.com,sony.com,facebook.com,twitter.com,instagram.com"];
	########################################## Enter URL's Here
    :local i 0;
    :local sum 0;
    :local method {""}
    :local retry 0;
    :local result {""};
	:local results {","};
	:local thisMany [:len $weburl];
    :local underRun 0;
    :local overRun 0;
    :put "###### Getting remote DNS servers for performance testing ######";
    :local manDnsServers [/ ip dns get servers];
    :local dynDnsServers [/ ip dns get dynamic-servers];
    :local dnsServers ($manDnsServers , $dynDnsServers);
    ########################################## results Formatting
    :local formatResult do={
        :put "this is start time: $startTime";
        :put "this is end time: $endTime";
        :local finalTime ( $endTime - $startTime );
        :set $sum ( $sum + ( [ :pick $finalTime 0 2 ] * 60 * 60 ));
        :set $sum ( $sum + ( [ :pick $finalTime 3 5 ] * 60 ));
        :set $sum ( $sum + [ :pick $finalTime 6 8 ] );
        :set $sum ($sum);
        :put $sum;
        :set $overRun ($sum - 1);
		:set $underRun (1 - $sum);
        if ($sum <= 1) do={
            :local result "###### Test #$i OO-PASSED: Retries = $retry, Resolved $thisMany URL's in $sum seconds using $svr";
            :set ($results->i) $result;
        };
        if ($sum > 1) do={
            :local result "###### Test #$i XX-FAILED: Retries = $retry, Resolved $thisMany URL's in $sum seconds using $svr - That is $overRun more than it should be.";
            :set ($results->i) $result;
        };
    };
    ########################################## Results Formatting
    ########################################## Resolver
    :local resolver do={
         :local startTime [/system clock get time];
        :foreach element in=$weburl do={
            :set $method [resolve $element server $svr];
            :put "Start time: $startTime";
            :put "Trying $element";
            :do {:set $result [$method];} on-error={  
                :put "###### DNS Timeout.... Trying once more before aborting test"; :do {
                    :set $result [$method];
                    :return (:set $retry ($retry + 1));
                };
            };
             put "Success $result";
        };
        :local endTime [/system clock get time];
        :put "End time: $endTime";
        :put [$formatResult startTime=$startTime endTime=$endTime svr=$svr];
    };
    ########################################## Resolver
	########################################## Remote Tests
	:put "###### OKAY, Lets go...";
	:foreach svr in=$dnsServers do={
        :set retry 0;
		:set i ($i + 1);
		:put [:ip dns cache flush];
        /delay 1;
		:put "###### Test #$i. Testing directly with $svr ######";
		

        :put [$resolver svr=$svr weburl=$weburl retry=$retry method=$method sum=$sum];

        :put "This is the returned sum $sum";
	    ##################################### Remote Resolver
	};
	####################################### Remote Tests
	###################################### Print Final Results
	:put "#############################################";
	:put "Each test should take <1s in a healthy system.";
	:put "There should be 0 retries.";
	:put "#############################################";
	:foreach i in=$results do={
		:put $i;
	};
	###################################### Print Final Results
};
$checkDNS;
