output "cluster_name" {
  value = aws_eks_cluster.main.name
}

output "cluster_endpoint" {
  value = aws_eks_cluster.main.endpoint
}

output "cluster_arn" {
  value = aws_eks_cluster.main.arn
}

output "cluster_ca" {
  value = aws_eks_cluster.main.certificate_authority[0].data
}

output "node_security_group_id" {
  value = aws_eks_cluster.main.vpc_config[0].cluster_security_group_id
}

output "oidc_provider" {
  value = replace(aws_eks_cluster.main.identity[0].oidc[0].issuer, "https://", "")
}

output "oidc_provider_arn" {
  value = aws_iam_openid_connect_provider.eks.arn
}
