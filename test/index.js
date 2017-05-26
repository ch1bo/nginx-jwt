import assert from 'assert';
import fetch from 'node-fetch';

describe('nginx_jwt', () => {

  describe('integration setup', () => {
    it('works correctly', () => {
      return fetch('http://nginx-jwt/')
        .then((response) => {
          assert.equal(200, response.status);
        });
    });
  });

  // TODO(SN): test with all supported different algs
  // TODO(SN): test with keys from file

  describe('jwt_issue', () => {
    function parseBase64(data) {
      return JSON.parse(new Buffer(data, 'base64').toString('ascii'));
    }

    function parseToken(data) {
      const parts = data.split('.');
      const token = {
        header: parseBase64(parts[0]),
        body: parseBase64(parts[1])
      };
      return token.header && token.body && token
    }

    function assertHeader(expectedAlg, header) {
      assert.equal('JWT', header.typ);
      assert.equal(header.alg, expectedAlg);
    }

    function assertToken(expectedAlg, expectedBody, token) {
      assertHeader(expectedAlg, token.header);
      assert.deepEqual(token.body, expectedBody);
    }

    it('returns token in response body', () => {
      const expected = { user: 'test', password: 'secret' };
      return fetch('http://nginx-jwt/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(expected)
      }).then((response) => response.text())
        .then(parseToken)
        .then((token) => assertToken('HS512', expected, token));
    });

    it('supports large (~800K) bodies', () => {
      const manyGrants = Array.from({length: 100000}, () => 'grant');
      return fetch('http://nginx-jwt/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ password: 'secret', authorization: manyGrants })
      }).then((response) => response.text())
        .then(parseToken)
        .then((token) => assertHeader('HS512', token.header));
    });

    it('returns 413 on too large (> 1M) bodies', () => {
      const tooManyGrants = Array.from({length: 200000}, () => 'auth');
      return fetch('http://nginx-jwt/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ password: 'secret', authorization: tooManyGrants })
      }).then((response) => assert.equal(response.status, 413));
    });
  });

  describe('jwt_verify', () => {
    function encodeBase64(json) {
      return new Buffer(JSON.stringify(json)).toString('base64');
    }

    it('returns 401 without token', () => {
      return fetch('http://nginx-jwt/api')
        .then((response) => {
          assert.equal(response.status, 401);
        });
    });

    it('returns 401 on invalid tokens', () => {
      return fetch('http://nginx-jwt/api', {
        headers: { authorization: 'definitely not a token' }
      }).then((response) => {
        assert.equal(response.status, 401);
      });
    });

    it('returns 401 on forged token', () => {
      const invalidToken =
              encodeBase64({ typ: 'JWT', alg: 'HS512' }) + '.' +
              encodeBase64({ request: 'some api request' }) + '.' +
              new Buffer('definitely not a signature').toString('ascii');
      return fetch('http://nginx-jwt/api', {
        headers: { authorization: invalidToken }
      }).then((response) => {
        assert.equal(response.status, 401);
      });
    });

    it('verifies tokens issued by jwt_issue', () => {
       return fetch('http://nginx-jwt/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ credentials: 'something secret' })
      })
        .then((response) => response.text())
        .then((token) => {
          return fetch('http://nginx-jwt/api', {
           headers: { authorization: token }
         });
        })
        .then((response) => assert.equal(response.status, 200));
    });
  });
});
