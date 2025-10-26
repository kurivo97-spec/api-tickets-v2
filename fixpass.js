// fixpass.js
const bcrypt = require('bcryptjs');

const password = '123456';
const salt = bcrypt.genSaltSync(10);
const hash = bcrypt.hashSync(password, salt);

console.log('Tu nuevo hash para 123456 es:');
console.log(hash);