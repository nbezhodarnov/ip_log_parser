# syntax=docker/dockerfile:1

FROM perl:latest

COPY . .

CMD [ "perl", "main.pl" ]
