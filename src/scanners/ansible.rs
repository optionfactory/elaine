use crate::scanners::pathcollector::Pattern;
use crate::scanners::{CheckStatus, RepoStats, ScanContext, Scanner, ScannerKind};
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub struct AnsibleScanner;
impl Scanner for AnsibleScanner {
    fn patterns(&self) -> Vec<(&'static str, Pattern)> {
        vec![
            ("ansible_confs", Pattern::FileName("ansible.cfg".to_string())),
            (
                "yaml_files",
                Pattern::FileNamePattern(Box::new(|name| name.ends_with(".yml") || name.ends_with(".yaml"))),
            ),
        ]
    }
    fn scan(&self, ctx: &ScanContext, stats: &mut RepoStats) -> anyhow::Result<()> {
        if ctx.repo.archived || ctx.repo.fork || ctx.repo.disabled {
            return Ok(());
        }
        let Some(confs) = ctx.matches.get("ansible_confs").filter(|confs| !confs.is_empty()) else {
            return Ok(());
        };
        stats.ansible_confs = confs.clone();
        ctx.set_message(format!("[{}] Reading the container images of the playbooks...", ctx.repo.name));
        let projects: Vec<&Path> = confs.iter().map(|conf| conf.parent().unwrap_or(Path::new(""))).collect();
        // a symbolic link could point outside the unpacked archive
        let documents: Vec<(PathBuf, Value)> = ctx
            .matches
            .get("yaml_files")
            .into_iter()
            .flatten()
            .filter(|path| projects.iter().any(|project| path.starts_with(project)))
            .filter(|path| ctx.root.join(path).symlink_metadata().is_ok_and(|meta| meta.file_type().is_file()))
            .filter_map(|path| {
                let text = std::fs::read_to_string(ctx.root.join(path)).ok()?;
                let document = serde_saphyr::from_str::<Value>(&text).ok()?;
                Some((path.clone(), document))
            })
            .collect();
        let (images, unresolved) = container_images(&documents);
        let known: BTreeSet<String> = stats.containers.iter().flatten().cloned().collect();
        stats.add_containers(images.into_iter().filter(|image| !known.contains(image)).collect());
        if unresolved.is_empty() {
            stats.record_check(ScannerKind::Ansible, "containers", CheckStatus::Ok);
        } else {
            let listed: Vec<String> = unresolved.into_iter().collect();
            ctx.report_failure("ansible", format!("Container images with unresolved variables: {}", listed.join(", ")));
            stats.record_check(ScannerKind::Ansible, "containers", CheckStatus::Failed);
        }
        Ok(())
    }
}

/// The string values of the `image` keys in playbooks and task files, with their `{{ a.b }}` references resolved
/// against the variables of each inventory (the `group_vars` and `host_vars` in the same directory), under the `vars`
/// of the play the image is in: one image per distinct result. The images nothing resolves are returned apart, as
/// written. Playbooks and task files are the YAML documents that are a list: a `pinch.yaml`, a `docker-compose.yml`
/// or a GitHub workflow is a mapping, with variables Ansible does not know.
fn container_images(documents: &[(PathBuf, Value)]) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut inventories: BTreeMap<PathBuf, Map<String, Value>> = BTreeMap::new();
    for (path, document) in documents {
        let Some(at) = path
            .components()
            .position(|c| matches!(c.as_os_str().to_str(), Some("group_vars" | "host_vars")))
        else {
            continue;
        };
        if let Value::Object(vars) = document {
            let inventory: PathBuf = path.components().take(at).collect();
            inventories.entry(inventory).or_default().extend(vars.clone());
        }
    }
    let no_vars = Map::new();
    let mut written: Vec<(String, &Map<String, Value>)> = Vec::new();
    for (_, document) in documents {
        if let Value::Array(plays) = document {
            for play in plays {
                let play_vars = play.get("vars").and_then(Value::as_object).unwrap_or(&no_vars);
                collect_images(play, play_vars, &mut written);
            }
        }
    }
    let reference = Regex::new(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)*)\s*\}\}").expect("valid regex");
    let mut images = BTreeSet::new();
    let mut unresolved = BTreeSet::new();
    for (image, play_vars) in written {
        if !image.contains("{{") {
            images.insert(image);
            continue;
        }
        let mut scopes: Vec<Map<String, Value>> = inventories.values().cloned().collect();
        if scopes.is_empty() {
            scopes.push(Map::new());
        }
        let resolved: BTreeSet<String> = scopes
            .into_iter()
            .filter_map(|mut vars| {
                vars.extend(play_vars.clone());
                let mut missing = false;
                let text = reference.replace_all(&image, |captures: &regex::Captures| {
                    lookup(&vars, &captures[1]).unwrap_or_else(|| {
                        missing = true;
                        String::new()
                    })
                });
                (!missing && !text.contains("{{")).then(|| text.into_owned())
            })
            .collect();
        if resolved.is_empty() {
            unresolved.insert(image);
        } else {
            images.extend(resolved);
        }
    }
    (images, unresolved)
}

fn lookup(vars: &Map<String, Value>, dotted: &str) -> Option<String> {
    let mut keys = dotted.split('.');
    let mut value = vars.get(keys.next()?)?;
    for key in keys {
        value = value.get(key)?;
    }
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        _ => None,
    }
}

fn collect_images<'a>(value: &Value, play_vars: &'a Map<String, Value>, images: &mut Vec<(String, &'a Map<String, Value>)>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if key == "image"
                    && let Value::String(image) = child
                {
                    images.push((image.clone(), play_vars));
                }
                collect_images(child, play_vars, images);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| collect_images(item, play_vars, images)),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn documents(files: &[(&str, &str)]) -> Vec<(PathBuf, Value)> {
        files
            .iter()
            .map(|(path, yaml)| (PathBuf::from(path), serde_saphyr::from_str::<Value>(yaml).expect("valid yaml fixture")))
            .collect()
    }

    #[test]
    fn images_take_their_tag_from_the_variables_of_the_inventory() {
        let found = container_images(&documents(&[
            ("cloud/ansible/production/group_vars/all/vars.yml", "images:\n  opfa: 257\n"),
            (
                "cloud/ansible/edge.yml",
                "- hosts: services\n  tasks:\n    - optionfactory.services.bundle:\n        container:\n          image: \"optionfactory/debian13-nginx130:{{ images.opfa }}\"\n",
            ),
            (
                "cloud/ansible/db.yml",
                "- hosts: db\n  tasks:\n    - community.docker.docker_container:\n        image: postgres:16\n",
            ),
        ]));
        let expected = (
            BTreeSet::from(["optionfactory/debian13-nginx130:257".to_string(), "postgres:16".to_string()]),
            BTreeSet::new(),
        );
        assert_eq!(found, expected);
    }

    #[test]
    fn inventories_with_different_values_give_one_image_each() {
        let found = container_images(&documents(&[
            ("inventories/production/group_vars/all.yml", "tag: \"1\"\n"),
            ("inventories/staging/group_vars/all.yml", "tag: \"2\"\n"),
            (
                "site.yml",
                "- hosts: all\n  tasks:\n    - docker_container:\n        image: \"app:{{ tag }}\"\n",
            ),
        ]));
        assert_eq!(found.0, BTreeSet::from(["app:1".to_string(), "app:2".to_string()]));
    }

    #[test]
    fn the_vars_of_the_play_win_over_the_inventory() {
        let found = container_images(&documents(&[
            ("group_vars/all.yml", "tag: \"1\"\n"),
            (
                "main.yml",
                "- hosts: all\n  vars:\n    tag: \"2\"\n    superset:\n      app_image: superset:5\n  tasks:\n    - docker_container:\n        image: \"app:{{ tag }}\"\n    - docker_container:\n        image: \"{{ superset.app_image }}\"\n",
            ),
        ]));
        assert_eq!(found.0, BTreeSet::from(["app:2".to_string(), "superset:5".to_string()]));
    }

    #[test]
    fn only_playbooks_and_task_files_are_read_for_images() {
        let found = container_images(&documents(&[
            (
                "pinch.yaml",
                "vars:\n  v: \"253\"\nprocesses:\n  - name: web\n    run:\n      type: docker\n      image: \"nginx:{{ v }}\"\n",
            ),
            ("roles/web/tasks/main.yml", "- docker_container:\n    image: postgres:16\n"),
        ]));
        assert_eq!(found, (BTreeSet::from(["postgres:16".to_string()]), BTreeSet::new()));
    }

    #[test]
    fn an_image_no_inventory_resolves_is_reported_as_written() {
        let found = container_images(&documents(&[
            ("group_vars/all.yml", "secret: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6162\n"),
            (
                "site.yml",
                "- hosts: all\n  tasks:\n    - docker_container:\n        image: \"{{ item.image | default('x') }}\"\n",
            ),
        ]));
        assert_eq!(found, (BTreeSet::new(), BTreeSet::from(["{{ item.image | default('x') }}".to_string()])));
    }
}
