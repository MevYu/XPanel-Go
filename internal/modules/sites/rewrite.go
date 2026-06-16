package sites

// 内置伪静态(rewrite)模板库,对标 aaPanel。键为模板 id,值为 nginx location/rewrite 片段。
// 这些片段作为站点 RewriteRules 写入 server 块;用户选用后仍会经 validNginxFragment + nginx -t。

// RewriteTemplate 是一条内置伪静态模板。
type RewriteTemplate struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

// rewriteTemplates 是模板库。内容为纯 location/rewrite 指令,可直接拼入 server 块。
var rewriteTemplates = []RewriteTemplate{
	{
		ID:      "none",
		Name:    "无",
		Content: "",
	},
	{
		ID:   "wordpress",
		Name: "WordPress",
		Content: `location / {
    try_files $uri $uri/ /index.php?$args;
}`,
	},
	{
		ID:   "laravel",
		Name: "Laravel",
		Content: `location / {
    try_files $uri $uri/ /index.php?$query_string;
}`,
	},
	{
		ID:   "thinkphp",
		Name: "ThinkPHP",
		Content: `location / {
    if (!-e $request_filename) {
        rewrite ^(.*)$ /index.php?s=$1 last;
    }
}`,
	},
	{
		ID:   "discuz",
		Name: "Discuz! X",
		Content: `location / {
    rewrite ^([^\.]*)/topic-(.+)\.html$ $1/portal.php?mod=topic&topic=$2 last;
    rewrite ^([^\.]*)/article-([0-9]+)-([0-9]+)\.html$ $1/portal.php?mod=view&aid=$2&page=$3 last;
    rewrite ^([^\.]*)/forum-(\w+)-([0-9]+)\.html$ $1/forum.php?mod=forumdisplay&fid=$2&page=$3 last;
    rewrite ^([^\.]*)/thread-([0-9]+)-([0-9]+)-([0-9]+)\.html$ $1/forum.php?mod=viewthread&tid=$2&extra=page%3D$4&page=$3 last;
    if (!-e $request_filename) {
        return 404;
    }
}`,
	},
	{
		ID:   "empirecms",
		Name: "EmpireCMS (帝国CMS)",
		Content: `location / {
    if (!-e $request_filename) {
        rewrite ^(.*)$ /index.php last;
    }
}`,
	},
	{
		ID:   "typecho",
		Name: "Typecho",
		Content: `location / {
    if (!-f $request_filename) {
        rewrite (.*) /index.php;
    }
}`,
	},
	{
		ID:   "yii2",
		Name: "Yii2",
		Content: `location / {
    try_files $uri $uri/ /index.php?$args;
}`,
	},
	{
		ID:   "codeigniter",
		Name: "CodeIgniter",
		Content: `location / {
    try_files $uri $uri/ /index.php?/$request_uri;
}`,
	},
	{
		ID:   "ecshop",
		Name: "ECShop",
		Content: `location / {
    rewrite "^/index\.html" /index.php last;
    rewrite "^/category$" /index.php last;
    if (!-e $request_filename) {
        rewrite "^/(.*)$" /index.php last;
    }
}`,
	},
	{
		ID:   "drupal",
		Name: "Drupal",
		Content: `location / {
    try_files $uri /index.php?$query_string;
}`,
	},
	{
		ID:   "phpwind",
		Name: "phpwind",
		Content: `location / {
    if (!-e $request_filename) {
        rewrite ^/(.*)$ /index.php?$1 last;
    }
}`,
	},
}

// listRewriteTemplates 返回全部内置模板。
func listRewriteTemplates() []RewriteTemplate { return rewriteTemplates }
