/*
 * Copyright © 2018 Lisk Foundation
 *
 * See the LICENSE file at the top-level directory of this distribution
 * for licensing information.
 *
 * Unless otherwise agreed in a custom licensing agreement with the Lisk Foundation,
 * no part of this software, including this file, may be copied, modified,
 * propagated, or distributed except according to the terms contained in the
 * LICENSE file.
 *
 * Removal or modification of this copyright notice is prohibited.
 */

'use strict';

var crypto = require('crypto');
var _ = require('lodash');
var async = require('async');
var BlockReward = require('../../logic/block_reward.js');
var constants = require('../../helpers/constants.js');
var slots = require('../../helpers/slots.js');
var exceptions = require('../../helpers/exceptions.js');

var modules;
var library;
var self;
var __private = {};

__private.lastNBlockIds = [];

/**
 * Description of the class.
 *
 * @class
 * @memberof modules.blocks
 * @see Parent: {@link modules.blocks}
 * @requires async
 * @requires crypto
 * @requires lodash
 * @requires helpers/constants
 * @requires helpers/exceptions
 * @requires helpers/slots
 * @requires logic/block_reward
 * @todo Add @param tags
 * @todo Add description for the class
 */
function Verify(logger, block, transaction, db) {
	library = {
		logger,
		db,
		logic: {
			block,
			transaction,
		},
	};
	self = this;
	__private.blockReward = new BlockReward();
	library.logger.trace('Blocks->Verify: Submodule initialized.');
	return self;
}

/**
 * Check transaction - perform transaction validation when processing block.
 * FIXME: Some checks are probably redundant, see: logic.transactionPool
 *
 * @private
 * @func checkTransaction
 * @param {Object} block - Block object
 * @param {Object} transaction - Transaction object
 * @param {function} cb - Callback function
 * @returns {function} cb - Callback function from params (through setImmediate)
 * @returns {Object} cb.err - Error if occurred
 */
__private.checkTransaction = function(block, transaction, cb) {
	async.waterfall(
		[
			function(waterCb) {
				try {
					// Calculate transaction ID
					// FIXME: Can have poor performance, because of hash cancluation
					transaction.id = library.logic.transaction.getId(transaction);
				} catch (e) {
					return setImmediate(waterCb, e.toString());
				}
				// Apply block ID to transaction
				transaction.blockId = block.id;
				return setImmediate(waterCb);
			},
			function(waterCb) {
				// Check if transaction is already in database, otherwise fork 2.
				// DATABASE: read only
				library.logic.transaction.checkConfirmed(transaction, err => {
					if (err) {
						// Fork: Transaction already confirmed.
						modules.delegates.fork(block, 2);
						// Undo the offending transaction.
						// DATABASE: write
						modules.transactions.undoUnconfirmed(transaction, err2 => {
							modules.transactions.removeUnconfirmedTransaction(transaction.id);
							return setImmediate(waterCb, err2 || err);
						});
					} else {
						return setImmediate(waterCb);
					}
				});
			},
			function(waterCb) {
				// Get account from database if any (otherwise cold wallet).
				// DATABASE: read only
				modules.accounts.getAccount(
					{ publicKey: transaction.senderPublicKey },
					waterCb
				);
			},
			function(sender, waterCb) {
				// Check if transaction id valid against database state (mem_* tables).
				// DATABASE: read only
				library.logic.transaction.verify(transaction, sender, waterCb);
			},
		],
		err => setImmediate(cb, err)
	);
};

/**
 * Set height according to the given last block.
 *
 * @private
 * @func setHeight
 * @param {Object} block - Target block
 * @param {Object} lastBlock - Last block
 * @returns {Object} block - Target block
 */
__private.setHeight = function(block, lastBlock) {
	try {
		block.height = lastBlock.height + 1;
	} catch (err) {
		return err;
	}
	return block;
};

/**
 * Verify block signature.
 *
 * @private
 * @func verifySignature
 * @param {Object} block - Target block
 * @param {Object} result - Verification results
 * @returns {Object} result - Verification results
 * @returns {boolean} result.verified - Indicator that verification passed
 * @returns {Array} result.errors - Array of validation errors
 */
__private.verifySignature = function(block, result) {
	var valid;

	try {
		valid = library.logic.block.verifySignature(block);
	} catch (e) {
		result.errors.push(e.toString());
	}

	if (!valid) {
		result.errors.push('Failed to verify block signature');
	}

	return result;
};

/**
 * Verify previous block.
 *
 * @private
 * @func verifyPreviousBlock
 * @param {Object} block - Target block
 * @param {Object} result - Verification results
 * @returns {Object} result - Verification results
 * @returns {boolean} result.verified - Indicator that verification passed
 * @returns {Array} result.errors - Array of validation errors
 */
__private.verifyPreviousBlock = function(block, result) {
	try {
		if (!block.previousBlock && block.height !== 1) {
			result.errors.push('Invalid previous block');
		}
	} catch (e) {
		result.errors.push(e.toString());
	}

	return result;
};

/**
 * Verify block is not one of the last {constants.blockSlotWindow} saved blocks.
 *
 * @private
 * @func verifyAgainstLastNBlockIds
 * @param {Object} block - Target block
 * @param {Object} result - Verification results
 * @returns {Object} result - Verification results
 * @returns {boolean} result.verified - Indicator that verification passed
 * @returns {Array} result.errors - Array of validation errors
 */
__private.verifyAgainstLastNBlockIds = function(block, result) {
	try {
		if (__private.lastNBlockIds.indexOf(block.id) !== -1) {
			result.errors.push('Block already exists in chain');
		}
	} catch (e) {
		result.errors.push(e.toString());
	}

	return result;
};

/**
 * Verify block version.
 *
 * @private
 * @func verifyVersion
 * @param {Object} block - Target block
 * @param {Object} result - Verification results
 * @returns {Object} result - Verification results
 * @returns {boolean} result.verified - Indicator that verification passed
 * @returns {Array} result.errors - Array of validation errors
 */
__private.verifyVersion = function(block, result) {
	if (block.version > 0) {
		result.errors.push('Invalid block version');
	}

	return result;
};

/**
 * Verify block reward.
 *
 * @private
 * @func verifyReward
 * @param {Object} block - Target block
 * @param {Object} result - Verification results
 * @returns {Object} result - Verification results
 * @returns {boolean} result.verified - Indicator that verification passed
 * @returns {Array} result.errors - Array of validation errors
 */
__private.verifyReward = function(block, result) {
	var expectedReward = __private.blockReward.calcReward(block.height);

	if (
		block.height !== 1 &&
		expectedReward !== block.reward &&
		exceptions.blockRewards.indexOf(block.id) === -1
	) {
		result.errors.push(
			['Invalid block reward:', block.reward, 'expected:', expectedReward].join(
				' '
			)
		);
	}

	return result;
};

/**
 * Verify block id.
 *
 * @private
 * @func verifyId
 * @param {Object} block - Target block
 * @param {Object} result - Verification results
 * @returns {Object} result - Verification results
 * @returns {boolean} result.verified - Indicator that verification passed
 * @returns {Array} result.errors - Array of validation errors
 */
__private.verifyId = function(block, result) {
	try {
		// Get block ID
		// FIXME: Why we don't have it?
		block.id = library.logic.block.getId(block);
	} catch (e) {
		result.errors.push(e.toString());
	}

	return result;
};

/**
 * Verify block payload (transactions).
 *
 * @private
 * @func verifyPayload
 * @param {Object} block - Target block
 * @param {Object} result - Verification results
 * @returns {Object} result - Verification results
 * @returns {boolean} result.verified - Indicator that verification passed
 * @returns {Array} result.errors - Array of validation errors
 */
__private.verifyPayload = function(block, result) {
	if (block.payloadLength > constants.maxPayloadLength) {
		result.errors.push('Payload length is too long');
	}

	if (block.transactions.length !== block.numberOfTransactions) {
		result.errors.push(
			'Included transactions do not match block transactions count'
		);
	}

	if (block.transactions.length > constants.maxTxsPerBlock) {
		result.errors.push('Number of transactions exceeds maximum per block');
	}

	var totalAmount = 0;
	var totalFee = 0;
	var payloadHash = crypto.createHash('sha256');
	var appliedTransactions = {};

	for (var i in block.transactions) {
		var transaction = block.transactions[i];
		var bytes;

		try {
			bytes = library.logic.transaction.getBytes(transaction);
		} catch (e) {
			result.errors.push(e.toString());
		}

		if (appliedTransactions[transaction.id]) {
			result.errors.push(
				`Encountered duplicate transaction: ${transaction.id}`
			);
		}

		appliedTransactions[transaction.id] = transaction;
		if (bytes) {
			payloadHash.update(bytes);
		}
		totalAmount += transaction.amount;
		totalFee += transaction.fee;
	}

	if (payloadHash.digest().toString('hex') !== block.payloadHash) {
		result.errors.push('Invalid payload hash');
	}

	if (totalAmount !== block.totalAmount) {
		result.errors.push('Invalid total amount');
	}

	if (totalFee !== block.totalFee) {
		result.errors.push('Invalid total fee');
	}

	return result;
};

/**
 * Verify block for fork cause one.
 *
 * @private
 * @func verifyForkOne
 * @param {Object} block - Target block
 * @param {Object} lastBlock - Last block
 * @param {Object} result - Verification results
 * @returns {Object} result - Verification results
 * @returns {boolean} result.verified - Indicator that verification passed
 * @returns {Array} result.errors - Array of validation errors
 */
__private.verifyForkOne = function(block, lastBlock, result) {
	if (block.previousBlock && block.previousBlock !== lastBlock.id) {
		modules.delegates.fork(block, 1);
		result.errors.push(
			[
				'Invalid previous block:',
				block.previousBlock,
				'expected:',
				lastBlock.id,
			].join(' ')
		);
	}

	return result;
};

/**
 * Verify block slot according to timestamp.
 *
 * @private
 * @func verifyBlockSlot
 * @param {Object} block - Target block
 * @param {Object} lastBlock - Last block
 * @param {Object} result - Verification results
 * @returns {Object} result - Verification results
 * @returns {boolean} result.verified - Indicator that verification passed
 * @returns {Array} result.errors - Array of validation errors
 */
__private.verifyBlockSlot = function(block, lastBlock, result) {
	var blockSlotNumber = slots.getSlotNumber(block.timestamp);
	var lastBlockSlotNumber = slots.getSlotNumber(lastBlock.timestamp);

	if (
		blockSlotNumber > slots.getSlotNumber() ||
		blockSlotNumber <= lastBlockSlotNumber
	) {
		result.errors.push('Invalid block timestamp');
	}

	return result;
};

/**
 * Verify block slot window according to application time.
 *
 * @private
 * @func verifyBlockSlotWindow
 * @param {Object} block - Target block
 * @returns {Object} result - Verification results
 * @returns {boolean} result.verified - Indicator that verification passed
 * @returns {Array} result.errors - Array of validation errors
 */
__private.verifyBlockSlotWindow = function(block, result) {
	var currentApplicationSlot = slots.getSlotNumber();
	var blockSlot = slots.getSlotNumber(block.timestamp);

	// Reject block if it's slot is older than constants.blockSlotWindow
	if (currentApplicationSlot - blockSlot > constants.blockSlotWindow) {
		result.errors.push('Block slot is too old');
	}

	// Reject block if it's slot is in the future
	if (currentApplicationSlot < blockSlot) {
		result.errors.push('Block slot is in the future');
	}

	return result;
};

/**
 * Verify block before fork detection and return all possible errors related to block.
 *
 * @param {Object} block - Full block
 * @returns {Object} result - Verification results
 * @returns {boolean} result.verified - Indicator that verification passed
 * @returns {Array} result.errors - Array of validation errors
 */
Verify.prototype.verifyReceipt = function(block) {
	var lastBlock = modules.blocks.lastBlock.get();

	block = __private.setHeight(block, lastBlock);

	var result = { verified: false, errors: [] };

	result = __private.verifySignature(block, result);
	result = __private.verifyPreviousBlock(block, result);
	result = __private.verifyAgainstLastNBlockIds(block, result);
	result = __private.verifyBlockSlotWindow(block, result);
	result = __private.verifyVersion(block, result);
	result = __private.verifyReward(block, result);
	result = __private.verifyId(block, result);
	result = __private.verifyPayload(block, result);

	result.verified = result.errors.length === 0;
	result.errors.reverse();

	return result;
};

/**
 * Loads last {constants.blockSlotWindow} blocks from the database into memory. Called when application triggeres blockchainReady event.
 */
Verify.prototype.onBlockchainReady = function() {
	return library.db.blocks
		.loadLastNBlockIds(constants.blockSlotWindow)
		.then(blockIds => {
			__private.lastNBlockIds = _.map(blockIds, 'id');
		})
		.catch(err => {
			library.logger.error(
				`Unable to load last ${constants.blockSlotWindow} block ids`
			);
			library.logger.error(err);
		});
};

/**
 * Maintains __private.lastNBlock variable - a queue of fixed length (constants.blockSlotWindow). Called when application triggers newBlock event.
 *
 * @func onNewBlock
 * @param {block} block
 * @todo Add description for the params
 */
Verify.prototype.onNewBlock = function(block) {
	__private.lastNBlockIds.push(block.id);
	if (__private.lastNBlockIds.length > constants.blockSlotWindow) {
		__private.lastNBlockIds.shift();
	}
};

/**
 * Verify block before processing and return all possible errors related to block.
 *
 * @param {Object} block - Full block
 * @returns {Object} result - Verification results
 * @returns {boolean} result.verified - Indicator that verification passed
 * @returns {Array} result.errors - Array of validation errors
 */
Verify.prototype.verifyBlock = function(block) {
	var lastBlock = modules.blocks.lastBlock.get();

	block = __private.setHeight(block, lastBlock);

	var result = { verified: false, errors: [] };

	result = __private.verifySignature(block, result);
	result = __private.verifyPreviousBlock(block, result);
	result = __private.verifyVersion(block, result);
	result = __private.verifyReward(block, result);
	result = __private.verifyId(block, result);
	result = __private.verifyPayload(block, result);

	result = __private.verifyForkOne(block, lastBlock, result);
	result = __private.verifyBlockSlot(block, lastBlock, result);

	result.verified = result.errors.length === 0;
	result.errors.reverse();

	return result;
};

/**
 * Adds default properties to block.
 *
 * @param {Object} block - Block object reduced
 * @returns {Object} Block object completed
 */
Verify.prototype.addBlockProperties = function(block) {
	if (block.version === undefined) {
		block.version = 0;
	}
	if (block.numberOfTransactions === undefined) {
		if (block.transactions === undefined) {
			block.numberOfTransactions = 0;
		} else {
			block.numberOfTransactions = block.transactions.length;
		}
	}
	if (block.totalAmount === undefined) {
		block.totalAmount = 0;
	}
	if (block.totalFee === undefined) {
		block.totalFee = 0;
	}
	if (block.payloadLength === undefined) {
		block.payloadLength = 0;
	}
	if (block.reward === undefined) {
		block.reward = 0;
	}
	if (block.transactions === undefined) {
		block.transactions = [];
	}
	return block;
};

/**
 * Deletes default properties from block.
 *
 * @param {Object} block - Block object completed
 * @returns {Object} Block object reduced
 */
Verify.prototype.deleteBlockProperties = function(block) {
	var reducedBlock = JSON.parse(JSON.stringify(block));
	if (reducedBlock.version === 0) {
		delete reducedBlock.version;
	}
	// verifyBlock ensures numberOfTransactions is transactions.length
	if (typeof reducedBlock.numberOfTransactions === 'number') {
		delete reducedBlock.numberOfTransactions;
	}
	if (reducedBlock.totalAmount === 0) {
		delete reducedBlock.totalAmount;
	}
	if (reducedBlock.totalFee === 0) {
		delete reducedBlock.totalFee;
	}
	if (reducedBlock.payloadLength === 0) {
		delete reducedBlock.payloadLength;
	}
	if (reducedBlock.reward === 0) {
		delete reducedBlock.reward;
	}
	if (reducedBlock.transactions && reducedBlock.transactions.length === 0) {
		delete reducedBlock.transactions;
	}
	return reducedBlock;
};

/**
 * Main function to process a block:
 * - Verify the block looks ok
 * - Verify the block is compatible with database state (DATABASE readonly)
 * - Apply the block to database if both verifications are ok
 *
 * @param {Object} block - Full block
 * @param {boolean} broadcast - Indicator that block needs to be broadcasted
 * @param {function} cb - Callback function
 * @param {boolean} saveBlock - Indicator that block needs to be saved to database
 * @returns {function} cb - Callback function from params (through setImmediate)
 * @returns {Object} cb.err - Error if occurred
 */
Verify.prototype.processBlock = function(block, broadcast, saveBlock, cb) {
	if (modules.blocks.isCleaning.get()) {
		// Break processing if node shutdown reqested
		return setImmediate(cb, 'Cleaning up');
	} else if (!__private.loaded) {
		// Break processing if blockchain is not loaded
		return setImmediate(cb, 'Blockchain is loading');
	}

	async.series(
		{
			addBlockProperties(seriesCb) {
				if (!broadcast) {
					try {
						// Set default properties
						block = self.addBlockProperties(block);
					} catch (err) {
						return setImmediate(seriesCb, err);
					}
				}

				return setImmediate(seriesCb);
			},
			normalizeBlock(seriesCb) {
				try {
					block = library.logic.block.objectNormalize(block);
				} catch (err) {
					return setImmediate(seriesCb, err);
				}

				return setImmediate(seriesCb);
			},
			verifyBlock(seriesCb) {
				// Sanity check of the block, if values are coherent
				// No access to database
				var result = self.verifyBlock(block);

				if (!result.verified) {
					library.logger.error(
						['Block', block.id, 'verification failed'].join(' '),
						result.errors[0]
					);
					return setImmediate(seriesCb, result.errors[0]);
				}
				return setImmediate(seriesCb);
			},
			broadcastBlock(seriesCb) {
				if (broadcast) {
					try {
						// Delete default properties
						var reducedBlock = self.deleteBlockProperties(block);
						modules.blocks.chain.broadcastReducedBlock(reducedBlock, broadcast);
					} catch (err) {
						return setImmediate(seriesCb, err);
					}
				}

				return setImmediate(seriesCb);
			},
			checkExists(seriesCb) {
				// Check if block id is already in the database (very low probability of hash collision)
				// TODO: In case of hash-collision, to me it would be a special autofork...
				// DATABASE: read only
				library.db.blocks.blockExists(block.id).then(rows => {
					if (rows) {
						return setImmediate(
							seriesCb,
							['Block', block.id, 'already exists'].join(' ')
						);
					}
					return setImmediate(seriesCb);
				});
			},
			validateBlockSlot(seriesCb) {
				// Check if block was generated by the right active delagate. Otherwise, fork 3
				// DATABASE: Read only to mem_accounts to extract active delegate list
				modules.delegates.validateBlockSlot(block, err => {
					if (err) {
						// Fork: Delegate does not match calculated slot
						modules.delegates.fork(block, 3);
						return setImmediate(seriesCb, err);
					}
					return setImmediate(seriesCb);
				});
			},
			checkTransactions(seriesCb) {
				// Check against the mem_* tables that we can perform the transactions included in the block
				async.eachSeries(
					block.transactions,
					(transaction, eachSeriesCb) => {
						__private.checkTransaction(block, transaction, eachSeriesCb);
					},
					err => setImmediate(seriesCb, err)
				);
			},
		},
		err => {
			if (err) {
				return setImmediate(cb, err);
			}
			// The block and the transactions are OK i.e:
			// * Block and transactions have valid values (signatures, block slots, etc...)
			// * The check against database state passed (for instance sender has enough LSK, votes are under 101, etc...)
			// We thus update the database with the transactions values, save the block and tick it.
			modules.blocks.chain.applyBlock(block, saveBlock, cb);
		}
	);
};

/**
 * Handle modules initialization:
 * - accounts
 * - blocks
 * - delegates
 * - transactions
 *
 * @param {Object} scope - Exposed modules
 */
Verify.prototype.onBind = function(scope) {
	library.logger.trace('Blocks->Verify: Shared modules bind.');
	modules = {
		accounts: scope.accounts,
		blocks: scope.blocks,
		delegates: scope.delegates,
		transactions: scope.transactions,
	};

	// Set module as loaded
	__private.loaded = true;
};

module.exports = Verify;
