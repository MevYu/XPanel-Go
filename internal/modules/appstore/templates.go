package appstore

// compose 模板均为 text/template:
//   - .Name     已校验的实例名(compose 项目名/容器名前缀/卷名前缀)
//   - .Params.X 已校验的参数值;模板里一律经 yq 函数做 YAML 标量转义(双保险)
//
// 参数在进入模板前已通过 validateParams 白名单校验(端口为数字、密码为受限字符集、
// 无换行/无 YAML 元字符),yq 转义是第二道防线,确保即便校验被绕过也不破坏 YAML 结构。

const wordpressCompose = `services:
  db:
    image: mysql:8
    restart: unless-stopped
    environment:
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wordpress
      MYSQL_PASSWORD: {{yq .Params.db_password}}
      MYSQL_RANDOM_ROOT_PASSWORD: "yes"
    volumes:
      - db_data:/var/lib/mysql
  wordpress:
    image: wordpress:6
    restart: unless-stopped
    depends_on:
      - db
    ports:
      - "{{.Params.http_port}}:80"
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD: {{yq .Params.db_password}}
      WORDPRESS_DB_NAME: wordpress
    volumes:
      - wp_data:/var/www/html
volumes:
  db_data:
  wp_data:
`

const haloCompose = `services:
  halo:
    image: halohub/halo:2
    restart: unless-stopped
    ports:
      - "{{.Params.http_port}}:8090"
    volumes:
      - halo_data:/root/.halo2
volumes:
  halo_data:
`

const giteaCompose = `services:
  gitea:
    image: gitea/gitea:1
    restart: unless-stopped
    ports:
      - "{{.Params.http_port}}:3000"
      - "{{.Params.ssh_port}}:22"
    volumes:
      - gitea_data:/data
volumes:
  gitea_data:
`

const uptimeKumaCompose = `services:
  uptime-kuma:
    image: louislam/uptime-kuma:1
    restart: unless-stopped
    ports:
      - "{{.Params.http_port}}:3001"
    volumes:
      - kuma_data:/app/data
volumes:
  kuma_data:
`

const postgresCompose = `services:
  postgres:
    image: postgres:16
    restart: unless-stopped
    ports:
      - "{{.Params.port}}:5432"
    environment:
      POSTGRES_PASSWORD: {{yq .Params.password}}
      POSTGRES_DB: {{yq .Params.db}}
    volumes:
      - pg_data:/var/lib/postgresql/data
volumes:
  pg_data:
`

const redisCompose = `services:
  redis:
    image: redis:7
    restart: unless-stopped
    command: ["redis-server", "--requirepass", {{yq .Params.password}}]
    ports:
      - "{{.Params.port}}:6379"
    volumes:
      - redis_data:/data
volumes:
  redis_data:
`

const mysqlCompose = `services:
  mysql:
    image: mysql:8
    restart: unless-stopped
    ports:
      - "{{.Params.port}}:3306"
    environment:
      MYSQL_ROOT_PASSWORD: {{yq .Params.root_password}}
      MYSQL_DATABASE: {{yq .Params.db}}
    volumes:
      - mysql_data:/var/lib/mysql
volumes:
  mysql_data:
`

const n8nCompose = `services:
  n8n:
    image: n8nio/n8n:1
    restart: unless-stopped
    ports:
      - "{{.Params.http_port}}:5678"
    volumes:
      - n8n_data:/home/node/.n8n
volumes:
  n8n_data:
`
