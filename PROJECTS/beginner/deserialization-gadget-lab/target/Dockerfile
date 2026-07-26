# ©AngelaMos | 2026
# Dockerfile

FROM ruby:4.0.2-slim

RUN gem install --no-document sinatra rackup webrick

WORKDIR /app

COPY lib /app/lib
COPY target/app.rb /app/target/app.rb
COPY target/config.ru /app/config.ru

ENV RUBYOPT="-I/app/lib"

EXPOSE 4567

USER nobody

CMD ["rackup", "--server", "webrick", "--host", "0.0.0.0", "--port", "4567"]
