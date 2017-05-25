import assert from 'assert';
import fetch from 'node-fetch';

describe('nginx_jwt', () => {

  describe('normal proxy', () => {
    it('works correctly', () => {
      return fetch('http://nginx-jwt/')
        .then((response) => {
          assert.equal(200, response.status);
        });
    });
  });

  describe('jwt_issue', () => {

    function parseBase64(data) {
      return JSON.parse(new Buffer(data, 'base64').toString('ascii'));
    }

    function assertToken(expectedBody, data) {
      const parts = data.split('.');
      const header = parseBase64(parts[0]);
      assert.equal("JWT", header.typ);
      assert.equal("HS512", header.alg);
      const body = parseBase64(parts[1]);
      assert.deepEqual(expectedBody, body);
    }

    it('returns a token in response body', () => {
      const expected = { user: 'test', password: 'secret' };
      return fetch('http://nginx-jwt/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(expected)
      }).then((response) => response.text())
        .then((data) => assertToken(expected, data));
    });
  });

  describe('jwt_verify', () => {
    it('returns 401 without token', () => {
      return fetch('http://nginx-jwt/api')
        .then((response) => {
          assert.equal(401, response.status);
        });
    });
  });
});
