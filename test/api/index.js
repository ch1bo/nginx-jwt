import express from 'express';
import bodyParser from 'body-parser';
import morgan from 'morgan';

let app = express();
app.use(bodyParser.json({ limit: '10mb' }));
app.use(morgan('dev'));

app.get('/', (req, res) => {
  res.send('Hello World');
});
app.post('/login', (req, res) => {
  res.json(req.body);
})
app.get('/api', (req, res) => {
  res.json({ message: 'api response' });
});
app.post('/api/echo', (req, res) => {
  res.json(req.body);
});

app.listen(80);
console.log('Test api started');
