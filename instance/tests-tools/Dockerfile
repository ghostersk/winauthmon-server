FROM python:alpine

# Environment variables for PostgreSQL and Redis
# openssl rand -base64 18
ENV POSTGRES_DB=basedbapp \
    POSTGRES_USER=maindbuser \
    POSTGRES_PASSWORD='4rV+ICvrlz3js7MiSvuFqZ47' \
    REDIS_PASSWORD='JgA3Pa7XOWGHKws3JvzPz0vc' \
    PG_SHARED_BUFFERS='256MB' \
    PG_WORK_MEM='16MB' \
    PG_EFFECTIVE_CACHE_SIZE='768MB' \
    REDIS_MAXMEMORY='256mb' \
    TZ=Europe/London \
    GUID=1000 \
    UUID=1000 \
    GIT_REPO_URL=https://github.com/yourusername/your-repo.git

# Install dependencies (  sqlite3 libsqlite3-dev )
RUN groupadd -g $GUID appuser && \
    adduser -u $UUID -D appuser -s /bin/bash -m appuser && \
    apk add --no-cache postgresql postgresql-dev redis net-tools \
    iputils-ping git curl openssl && \
    git clone $GIT_REPO_URL /app && chown -R appuser:appuser /app

# Initialize PostgreSQL
RUN mkdir -p /run/postgresql && chown postgres:postgres /run/postgresql
USER postgres
RUN initdb -D /var/lib/postgresql/data && \
    echo "shared_buffers = $PG_SHARED_BUFFERS" >> /var/lib/postgresql/data/postgresql.conf && \
    echo "work_mem = $PG_WORK_MEM" >> /var/lib/postgresql/data/postgresql.conf && \
    echo "effective_cache_size = $PG_EFFECTIVE_CACHE_SIZE" >> /var/lib/postgresql/data/postgresql.conf && \
    pg_ctl -D /var/lib/postgresql/data -l logfile start && \
    psql -c "CREATE USER \"$POSTGRES_USER\" WITH PASSWORD '$POSTGRES_PASSWORD';" && \
    createdb -O "$POSTGRES_USER" "$POSTGRES_DB" && \
    pg_ctl -D /var/lib/postgresql/data stop
USER root

# Configure Redis
RUN echo "requirepass $REDIS_PASSWORD" >> /etc/redis.conf && \
    echo "maxmemory $REDIS_MAXMEMORY" >> /etc/redis.conf && \
    echo "maxmemory-policy allkeys-lru" >> /etc/redis.conf

WORKDIR /app
USER appuser
RUN pip install --no-cache-dir -r requirements.txt && \
    /bin/bash instance/certs/gen_certs.sh

# Persistent volumes for PostgreSQL and Redis
VOLUME ["/var/lib/postgresql/data", "/data"]
# Postresql 5432 Redis 6379 
EXPOSE 8000

USER root
CMD service postgresql start && redis-server /etc/redis.conf --daemonize yes && su - appuser -c "python /app/app.py"