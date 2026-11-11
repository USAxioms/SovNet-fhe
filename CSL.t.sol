// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../contracts/CognitiveStateLedger.sol";

contract CSLTest is Test {
    CognitiveStateLedger public csl;
    address public primary = address(0x1);
    address public secondary = address(0x2);

    function setUp() public {
        csl = new CognitiveStateLedger(primary, secondary);
    }

    function test_InitialState() public view {
        assertEq(csl.primaryCustodian(), primary);
        assertEq(csl.secondaryCustodian(), secondary);
    }

    function test_CommitStateHash() public {
        bytes32 mockHash = keccak256("STATE_COMMITMENT_1");
        vm.prank(primary);
        csl.submitStateCommitment(mockHash);
        assertEq(csl.latestStateHash(), mockHash);
    }
}
