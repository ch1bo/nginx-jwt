import assert from 'assert';
import fetch from 'node-fetch';

describe('jwt_issue', () => {
  it('should issue a token', () => {
    return fetch('http://test-api/login', {
      method : 'POST',
      body: {
        user: 'name',
        password: 'test'
      }})
      .then((response) => {
        assert.equal(200, response.statusCode);
      })
      .catch((error) => assert.fail(error));
  });
});
