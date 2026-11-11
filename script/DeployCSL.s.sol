// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../CognitiveStateLedger.sol";

contract DeployCSL is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address primaryCustodian = vm.envAddress("PRIMARY_CUSTODIAN");
        address secondaryCustodian = vm.envAddress("SECONDARY_CUSTODIAN");

        vm.startBroadcast(deployerPrivateKey);

        CognitiveStateLedger csl = new CognitiveStateLedger(
            primaryCustodian,
            secondaryCustodian
        );

        vm.stopBroadcast();

        console.log("CognitiveStateLedger deployed to:", address(csl));
    }
}
