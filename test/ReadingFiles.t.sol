import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
import {Vm} from "forge-std/Vm.sol";
import {ReadFile} from "../script/libs/ReadFile.sol";

contract ReadingFiles is Test {
    function run() external {}

    function testReadInput() public {
        ReadFile readFile = new ReadFile();
        address vaultFactory = readFile.readInput(11_155_111, "symbiotic", "VAULT_FACTORY");
        assertEq(vaultFactory, 0x407A039D94948484D356eFB765b3c74382A050B4);
    }
}
