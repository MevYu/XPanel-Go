package ssl

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// 域名白名单:小写/大写字母、数字、点、连字符,可含一级通配 "*."。
// 单标签 1-63 字符,总长 <= 253。拒绝任何可用于命令注入的字符。
var domainLabelRe = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`)

// ValidDomain 严格校验单个域名(可选一级 "*." 通配)。挡注入与畸形输入。
func ValidDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	if strings.ContainsAny(d, " \t\n\r;|&$`<>(){}[]\\'\"") {
		return false
	}
	// 通配只允许出现在最左标签且为整段 "*"。
	if strings.Contains(d, "*") && !strings.HasPrefix(d, "*.") {
		return false
	}
	if strings.Count(d, "*") > 1 {
		return false
	}
	return domainLabelRe.MatchString(d)
}

// ValidDomains 校验非空域名列表,全部合法才返回 true。
func ValidDomains(ds []string) bool {
	if len(ds) == 0 {
		return false
	}
	for _, d := range ds {
		if !ValidDomain(d) {
			return false
		}
	}
	return true
}

// ChallengeType 是 ACME 验证方式。
type ChallengeType string

const (
	ChallengeWebroot    ChallengeType = "webroot"    // HTTP-01,挑战写入 webroot 由 nginx 服务
	ChallengeStandalone ChallengeType = "standalone" // HTTP-01,CLI 自起临时服务器占 80 端口
	ChallengeDNS        ChallengeType = "dns"         // DNS-01,需 DNS 插件/手动
)

func validChallenge(c ChallengeType) bool {
	switch c {
	case ChallengeWebroot, ChallengeStandalone, ChallengeDNS:
		return true
	}
	return false
}

// IssueRequest 描述一次签发请求。Domains[0] 作为主域名。
type IssueRequest struct {
	Domains   []string
	Challenge ChallengeType
	Webroot   string // ChallengeWebroot 时的 web 根目录
	DNSPlugin string // ChallengeDNS 时的 DNS provider(如 "dns_cf"),空则手动模式
	KeyPath   string // 私钥落盘路径(0600)
	CertPath  string // 全链证书落盘路径
}

// ACME 抽象 ACME CLI,便于 mock 测试。实现绝不拼接 shell,全用参数数组。
type ACME interface {
	// Issue 签发证书并把私钥/全链写到 req.KeyPath/req.CertPath。
	Issue(req IssueRequest) error
	// Renew 续期指定主域名的证书并重新落盘到 keyPath/certPath。
	Renew(domain, keyPath, certPath string) error
	// Available 报告 CLI 是否可用(供 HealthCheck)。
	Available() error
	// Name 返回后端名(acme.sh / certbot),供展示。
	Name() string
}

// runner 抽象命令执行,测试可替换。生产用 execRunner。
type runner func(name string, args ...string) (string, error)

func execRunner(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("%s: %w", name, err)
	}
	return text, nil
}

// cliACME 是基于 acme.sh / certbot 的 ACME 实现。
type cliACME struct {
	backend string // "acme.sh" 或 "certbot"
	run     runner
}

// DetectACME 探测 PATH 中的 ACME CLI:优先 acme.sh,回退 certbot。
// 都不在返回 error(供 HealthCheck 拒绝启用)。
func DetectACME() (ACME, error) {
	return detectACME(exec.LookPath, execRunner)
}

func detectACME(lookPath func(string) (string, error), run runner) (ACME, error) {
	if _, err := lookPath("acme.sh"); err == nil {
		return &cliACME{backend: "acme.sh", run: run}, nil
	}
	if _, err := lookPath("certbot"); err == nil {
		return &cliACME{backend: "certbot", run: run}, nil
	}
	return nil, fmt.Errorf("ssl: no ACME client (acme.sh / certbot) in PATH")
}

func (c *cliACME) Name() string { return c.backend }

func (c *cliACME) Available() error {
	if _, err := exec.LookPath(c.backend); err != nil {
		return fmt.Errorf("ssl: %s not in PATH: %w", c.backend, err)
	}
	return nil
}

func (c *cliACME) Issue(req IssueRequest) error {
	if !ValidDomains(req.Domains) {
		return fmt.Errorf("ssl: invalid domain in request")
	}
	if !validChallenge(req.Challenge) {
		return fmt.Errorf("ssl: invalid challenge %q", req.Challenge)
	}
	if c.backend == "acme.sh" {
		return c.issueAcmeSh(req)
	}
	return c.issueCertbot(req)
}

func (c *cliACME) issueAcmeSh(req IssueRequest) error {
	args := []string{"--issue"}
	for _, d := range req.Domains {
		args = append(args, "-d", d)
	}
	switch req.Challenge {
	case ChallengeWebroot:
		if req.Webroot == "" {
			return fmt.Errorf("ssl: webroot required for webroot challenge")
		}
		args = append(args, "-w", req.Webroot)
	case ChallengeStandalone:
		args = append(args, "--standalone")
	case ChallengeDNS:
		if req.DNSPlugin == "" {
			args = append(args, "--dns", "--yes-I-know-dns-manual-mode-enough-go-ahead-please")
		} else {
			args = append(args, "--dns", req.DNSPlugin)
		}
	}
	if _, err := c.run(c.backend, args...); err != nil {
		return err
	}
	// 安装到面板期望的路径,供 nginx 引用。
	install := []string{"--install-cert", "-d", req.Domains[0],
		"--key-file", req.KeyPath, "--fullchain-file", req.CertPath}
	_, err := c.run(c.backend, install...)
	return err
}

func (c *cliACME) issueCertbot(req IssueRequest) error {
	args := []string{"certonly", "--non-interactive", "--agree-tos"}
	switch req.Challenge {
	case ChallengeWebroot:
		if req.Webroot == "" {
			return fmt.Errorf("ssl: webroot required for webroot challenge")
		}
		args = append(args, "--webroot", "-w", req.Webroot)
	case ChallengeStandalone:
		args = append(args, "--standalone")
	case ChallengeDNS:
		args = append(args, "--manual", "--preferred-challenges", "dns")
	}
	for _, d := range req.Domains {
		args = append(args, "-d", d)
	}
	args = append(args, "--key-path", req.KeyPath, "--fullchain-path", req.CertPath)
	_, err := c.run(c.backend, args...)
	return err
}

func (c *cliACME) Renew(domain, keyPath, certPath string) error {
	if !ValidDomain(domain) {
		return fmt.Errorf("ssl: invalid domain %q", domain)
	}
	if c.backend == "acme.sh" {
		if _, err := c.run(c.backend, "--renew", "-d", domain, "--force"); err != nil {
			return err
		}
		_, err := c.run(c.backend, "--install-cert", "-d", domain,
			"--key-file", keyPath, "--fullchain-file", certPath)
		return err
	}
	_, err := c.run(c.backend, "certonly", "--non-interactive", "--force-renewal",
		"-d", domain, "--key-path", keyPath, "--fullchain-path", certPath)
	return err
}
