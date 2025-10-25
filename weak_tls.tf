resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.my_lb.arn
  port              = 443
  protocol          = "HTTPS"

  ssl_policy = "ELBSecurityPolicy-2015-05"  # ❌ Outdated, weak TLS version
  certificate_arn = aws_acm_certificate.my_cert.arn
}