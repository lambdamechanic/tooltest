variable "repo_tag_prefix" {
  default = "tooltest"
}

variable "base_tag" {
  default = "${repo_tag_prefix}/dev-base:latest"
}

variable "agent_base_context" {
  default = "target:dev-base"
}

group "agents" {
  targets = [
    "dev-base",
    "agent-ampcode",
    "devtools",
  ]
}

group "default" {
  targets = [
    "dev-base",
    "agent-ampcode",
    "devtools",
  ]
}

target "dev-base" {
  context    = "."
  dockerfile = "docker/base/Dockerfile"
  tags       = ["${base_tag}"]
  platforms  = ["linux/amd64"]
}

target "agent-common" {
  context    = "."
  platforms  = ["linux/amd64"]
  depends_on = ["dev-base"]
  contexts = {
    base = "${agent_base_context}"
  }
  args = {
    BASE_IMAGE = "base"
  }
}

target "agent-ampcode" {
  inherits   = ["agent-common"]
  dockerfile = "docker/agents/ampcode.Dockerfile"
  tags       = ["isura/${repo_tag_prefix}-agent-ampcode:latest"]
}

target "devtools" {
  inherits   = ["agent-common"]
  dockerfile = "docker/agents/devtools.Dockerfile"
  tags       = ["${repo_tag_prefix}/devtools:latest"]
}
