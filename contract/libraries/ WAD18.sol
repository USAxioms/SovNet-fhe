// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title WAD18
 * @notice Fixed-Point Arithmetic Library for 18-decimal precision (WAD = 10^18).
 * @dev Guarantees deterministic, zero-drift integer arithmetic for high-precision
 *      state transitions, homomorphic plaintext encoding, and normative consensus ledgers.
 */
library WAD18 {
    uint256 internal constant WAD = 1e18;
    uint256 internal constant HALF_WAD = 0.5e18;

    error WadOverflow();
    error WadDivideByZero();

    /**
     * @notice Multiplies two WAD-18 fixed-point numbers with deterministic rounding to the nearest integer.
     * @param x First operand in WAD scale (1e18)
     * @param y Second operand in WAD scale (1e18)
     * @return z Result in WAD scale (1e18)
     */
    function wadMul(uint256 x, uint256 y) internal pure returns (uint256 z) {
        unchecked {
            if (x == 0 || y == 0) return 0;
            // The guard must cover x * y + HALF_WAD, not just x * y: this block is unchecked, so an
            // addition that wraps would silently return a wrong value instead of reverting.
            if (x > (type(uint256).max - HALF_WAD) / y) revert WadOverflow();

            // Add HALF_WAD for standard round-to-nearest behavior before scaling down
            z = (x * y + HALF_WAD) / WAD;
        }
    }

    /**
     * @notice Divides two WAD-18 fixed-point numbers with deterministic rounding.
     * @param x Numerator in WAD scale (1e18)
     * @param y Denominator in WAD scale (1e18)
     * @return z Result in WAD scale (1e18)
     */
    function wadDiv(uint256 x, uint256 y) internal pure returns (uint256 z) {
        unchecked {
            if (y == 0) revert WadDivideByZero();
            if (x == 0) return 0;

            if (x > (type(uint256).max - (y / 2)) / WAD) revert WadOverflow();

            z = (x * WAD + (y / 2)) / y;
        }
    }

    /**
     * @notice Scales a raw standard integer up to WAD-18 scale.
     * @param x Raw scalar quantity
     * @return z Quantity scaled to 1e18
     */
    function toWad(uint256 x) internal pure returns (uint256 z) {
        unchecked {
            if (x > type(uint256).max / WAD) revert WadOverflow();
            z = x * WAD;
        }
    }

    /**
     * @notice Truncates a WAD-18 fixed-point number back down to a raw scalar integer.
     * @param x Quantity in WAD scale (1e18)
     * @return z Raw scalar integer
     */
    function fromWad(uint256 x) internal pure returns (uint256 z) {
        unchecked {
            z = x / WAD;
        }
    }

    /**
     * @notice Computes the absolute difference between two WAD-18 values.
     */
    function wadAbsDiff(uint256 x, uint256 y) internal pure returns (uint256 z) {
        unchecked {
            z = x >= y ? x - y : y - x;
        }
    }
}
