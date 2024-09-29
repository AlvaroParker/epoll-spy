use std::collections::HashSet;

use procfs::process::Process;

pub fn get_threads(pids: &mut HashSet<u32>) {
    let mut tids = HashSet::new();
    let mut vec_children: Vec<HashSet<u32>> = Vec::new();
    for pid in pids.iter() {
        let raw_pid = match i32::try_from(*pid) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let proc = match Process::new(raw_pid) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let tasks = match proc.tasks() {
            Ok(t) => t,
            Err(_) => continue,
        };
        for task in tasks {
            if let Ok(task) = task {
                if let Ok(childrens) = task.children() {
                    let mut children_pids: HashSet<u32> =
                        childrens.iter().map(|i| i.to_owned()).collect();
                    get_threads(&mut children_pids);
                    vec_children.push(children_pids);
                }
                if task.tid > 0 && !pids.contains(&(task.tid as u32)) {
                    tids.insert(task.tid as u32);
                }
            }
        }
    }
    pids.extend(tids);
    for children in vec_children {
        pids.extend(children);
    }
}
