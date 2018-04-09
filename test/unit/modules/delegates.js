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

var genesisDelegates = require('../../data/genesis_delegates.json');
var accountFixtures = require('../../fixtures/accounts');
var application = require('../../common/application');

describe('delegates', () => {
	var library;

	before(done => {
		application.init(
			{ sandbox: { name: 'lisk_test_modules_delegates' } },
			(err, scope) => {
				library = scope;
				// Set delegates module as loaded to allow manual forging
				library.rewiredModules.delegates.__set__('__private.loaded', true);
				// Load forging delegates
				library.rewiredModules.delegates.__get__('__private');
				done(err);
			}
		);
	});

	after(done => {
		application.cleanup(done);
	});

	describe('__private', () => {
		describe('loadDelegates', () => {
			var loadDelegates;
			var config;
			var __private;

			var encryptedSecret = [
				{
					publicKey:
						'9d3058175acab969f41ad9b86f7a2926c74258670fe56b37c429c01fca9f2f0f',
					encryptedSecret:
						'5d6bca0692a99eebb4bcc67fbd1b55c6a4c21bb5578b70f57042b397457580e8ae922c59f8bb12c73028f30c625fd394e35a5b96764c5abb204cedbfc15f9dc5dbd5b981c138f2526f6c577d8a9e6b3e',
					iv: '4db430d52d862820edb29754bc9dfd20',
					salt: '74926b77fac5e1fce3ccef87634490e5',
					tag: '757d487cb2f09a95b2de021a494b4728',
					version: '1.0.0',
				},
				{
					publicKey:
						'141b16ac8d5bd150f16b1caa08f689057ca4c4434445e56661831f4e671b7c0a',
					encryptedSecret:
						'efdb41939ee2a13951645a757ebeceb03c74ea481e4ee2d046aeddcdce2101d52f76a2b46766fc6ebe27fa833ff6fde632350925bfb852dccb65f2aed024fc0f59d4bc8ef5527f03a54b7b60',
					iv: '9e12e55bbdc2e2c4e07b8f0dcdcb6952',
					salt: '71cfb1a5781f85997074b7844519b229',
					tag: '7ae22ddfd9a07efc827d95ec83669095',
					version: '1.0.0',
				},
				{
					publicKey:
						'3ff32442bb6da7d60c1b7752b24e6467813c9b698e0f278d48c43580da972135',
					encryptedSecret:
						'47a7d3f5f1c17574588024626da44b0d90f165a13b7e8820f642a50d0d9db06c251f0cd4bf0b7f6407caf7cd018255b7cc073c8367b1c4b8da60de47773e12159f4ff1993229b112e1a9f116a3e9',
					iv: '098f33427cd49a59f28dd95e3167f257',
					salt: 'f860e9257fd57ec396daa75b673b311c',
					tag: '416f0c8416ed972d1fb13ecabd4bc20b',
					version: '1.0.0',
				},
			];

			before(done => {
				loadDelegates = library.rewiredModules.delegates.__get__(
					'__private.loadDelegates'
				);
				config = library.rewiredModules.delegates.__get__('library.config');
				__private = library.rewiredModules.delegates.__get__('__private');
				done();
			});

			beforeEach(done => {
				__private.keypairs = {};
				config.forging.force = true;
				config.forging.secret = [];
				done();
			});

			it('should not load any delegates when forging.force is false', done => {
				config.forging.force = false;
				config.forging.secret = encryptedSecret;

				loadDelegates(err => {
					expect(err).to.not.exist;
					expect(Object.keys(__private.keypairs).length).to.equal(0);
					done();
				});
			});

			it('should not load any delegates when forging.secret array is empty', done => {
				config.forging.secret = [];

				loadDelegates(err => {
					expect(err).to.not.exist;
					expect(Object.keys(__private.keypairs).length).to.equal(0);
					done();
				});
			});

			it('should not load any delegates when forging.secret list is undefined', done => {
				config.forging.secret = undefined;

				loadDelegates(err => {
					expect(err).to.not.exist;
					expect(Object.keys(__private.keypairs).length).to.equal(0);
					done();
				});
			});

			it('should return error if encrypted secret does not decrypt with default secret', done => {
				var accountDetails = {
					publicKey:
						'9d3058175acab969f41ad9b86f7a2926c74258670fe56b37c429c01fca9f2f0f',
					// encryptedSecret is one character too short
					encryptedSecret:
						'5d6bca0692a99eebb4bcc67fbd1b55c6a4c21bb5578b70f57042b397457580e8ae922c59f8bb12c73028f30c625fd394e35a5b96764c5abb204cedbfc15f9dc5dbd5b981c138f2526f6c577d8a9e6b3',
					iv: '4db430d52d862820edb29754bc9dfd20',
					salt: '74926b77fac5e1fce3ccef87634490e5',
					tag: '757d487cb2f09a95b2de021a494b4728',
					version: '1.0.0',
				};

				config.forging.secret = [accountDetails];

				loadDelegates(err => {
					expect(err).to.equal(
						`Invalid encryptedSecret for publicKey: ${accountDetails.publicKey}`
					);
					expect(Object.keys(__private.keypairs).length).to.equal(0);
					done();
				});
			});

			it('should return error if publicKeys do not match', done => {
				var accountDetails = {
					publicKey:
						'141b16ac8d5bd150f16b1caa08f689057ca4c4434445e56661831f4e671b7c0a',
					encryptedSecret:
						'5d6bca0692a99eebb4bcc67fbd1b55c6a4c21bb5578b70f57042b397457580e8ae922c59f8bb12c73028f30c625fd394e35a5b96764c5abb204cedbfc15f9dc5dbd5b981c138f2526f6c577d8a9e6b3e',
					iv: '4db430d52d862820edb29754bc9dfd20',
					salt: '74926b77fac5e1fce3ccef87634490e5',
					tag: '757d487cb2f09a95b2de021a494b4728',
					version: '1.0.0',
				};

				config.forging.secret = [accountDetails];

				loadDelegates(err => {
					expect(err).to.equal('Public keys do not match');
					expect(Object.keys(__private.keypairs).length).to.equal(0);
					done();
				});
			});

			it('should return error if account does not exist', done => {
				var randomAccount = {
					secret:
						'robust swift deputy enable forget peasant grocery road convince',
					publicKey:
						'35b9364d1733e503599a1e9eefdb4994dd07bb9924acebfec06195cf1a0fa6db',
					encryptedSecret:
						'fd6467a4a5aa232b130ecab5b2998eb5590de99dfd9c414f6e6f86423d6f00ab4de3dd7287b0806ca2a0b353dbe1130d49f07d5c7cd72f8d9d52fa75168724',
					iv: '20c38a975a376d67640438e66c99ef7f',
					salt: 'a5ac11c77d71ee4396e16e7ced056d9f',
					tag: 'bbfe6b743c27397b4392e64843e4c926',
					version: '1.0.0',
				};
				var accountDetails = {
					encryptedSecret: randomAccount.encryptedSecret,
					publicKey: randomAccount.publicKey,
					iv: randomAccount.iv,
					salt: randomAccount.salt,
					tag: randomAccount.tag,
					version: randomAccount.version,
				};

				config.forging.secret = [accountDetails];

				loadDelegates(err => {
					expect(err).to.equal(
						[
							'Account with public key:',
							accountDetails.publicKey.toString('hex'),
							'not found',
						].join(' ')
					);
					expect(Object.keys(__private.keypairs).length).to.equal(0);
					done();
				});
			});

			it('should ignore secrets which do not belong to a delegate', done => {
				config.forging.secret = [
					{
						encryptedSecret: accountFixtures.genesis.encryptedSecret,
						publicKey: accountFixtures.genesis.publicKey,
						iv: accountFixtures.genesis.iv,
						salt: accountFixtures.genesis.salt,
						tag: accountFixtures.genesis.tag,
						version: accountFixtures.genesis.version,
					},
				];

				loadDelegates(err => {
					expect(err).to.not.exist;
					expect(Object.keys(__private.keypairs).length).to.equal(0);
					done();
				});
			});

			it('should load secrets in encrypted format with the key', done => {
				config.forging.secret = encryptedSecret;

				loadDelegates(err => {
					expect(err).to.not.exist;
					expect(Object.keys(__private.keypairs).length).to.equal(
						encryptedSecret.length
					);
					done();
				});
			});

			it('should load all 101 delegates', done => {
				config.forging.secret = genesisDelegates.delegates.map(delegate => ({
					encryptedSecret: delegate.encryptedSecret,
					iv: delegate.iv,
					salt: delegate.salt,
					tag: delegate.tag,
					publicKey: delegate.publicKey,
				}));

				loadDelegates(err => {
					expect(err).to.not.exist;
					expect(Object.keys(__private.keypairs).length).to.equal(101);
					done();
				});
			});
		});
	});
});
