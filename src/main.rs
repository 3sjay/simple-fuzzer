use std::env::args;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio, exit};
use std::time::Duration;
use std::fs;
use std::thread;
use std::path::Path;

use std::process;

use rand::{self, Rng};

use sha1::Sha1;

use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitStatus, wait};
use nix::unistd::{fork, ForkResult, Pid};

mod mutate;

/*
https://gitlab.com/gitlab-org/vulnerability-research/kb/presentations/creating_a_snapshot_feedback_guided_fuzzer/-/tree/master/examples/d_spawn_with_ptrace_mutate_snapshot


Generating ramdisk on osx:
----------
# ~2GB ramdisk
diskutil erasevolume HFS+ 'RAMDisk' `hdiutil attach -nomount ram://4388608`
->
mkdir /Volumes/RAMDisk/ramstuff
->
/Volumes/RAMDisk/ramstuff

*/


static NTHREADS: i64 = 200;

static mut COUNTER: u32 = 0;

static mut input_files: Vec<Vec<u8>> = vec![];


fn print_statistics() {
    loop {
        thread::sleep(Duration::from_secs(10));
        unsafe { 
            println!("Execs/sec: {:.2}", COUNTER/10);
            COUNTER = 0 
        };
    }
}

fn fill_up_input_files(dir: &Path) {
    if dir.is_dir() {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if !path.is_dir() {
								let mut input = Vec::new();
								input = fs::read(&entry.path()).unwrap();
								println!("[*] Adding file {:?} to fuzz input", &entry.path());
								unsafe { input_files.push(input.clone()) };
            }
        }
    }
}

fn run_child(cmd: &str, args: &Vec<String>) {
    ptrace::traceme().unwrap();

    //println!("[*] {} : {:?}", cmd, args);

    Command::new(cmd)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env("DYLD_INSERT_LIBRARIES", "/usr/lib/libgmalloc.dylib")
        .exec();

    exit(0);
}

fn run_parent(pid: Pid, file_contents: &Vec<u8>) {
    loop {
        match wait() {
            Ok(status) => {
                match status {
                    WaitStatus::Stopped(pid_t, sig_num) => {
                        match sig_num {
                            Signal::SIGSEGV => {
                                let mut hasher = Sha1::new();
                                hasher.update(file_contents);
                                let crash_filename = format!("crashfile_{}", hasher.digest().to_string());
                                println!("[+] Writing crash file: {}", crash_filename);
                                fs::write(crash_filename, file_contents).unwrap();
                                break
                            },

                            Signal::SIGABRT => {
                                let mut hasher = Sha1::new();
                                hasher.update(file_contents);
                                let crash_filename = format!("abrtfile_{}", hasher.digest().to_string());
                                println!("[+] Writing abort file: {}", crash_filename);
                                fs::write(crash_filename, file_contents).unwrap();
                                break
                            },
                            _ => {
                                ptrace::cont(pid_t, None).unwrap();
                            }
                        }
                    },
                    /*
                    Ok(WaitStatus::Exited(pid, exit_status)) => {
                        //println!("Process exited with status: {}", exit_status);
                        break
                    },
                    */

                    _ => {
                        //ptrace::cont(pid, Signal::SIGKILL).unwrap();
                        break
                    }

                }
            }

            Err(err) => {
                println!("Error in run_parent: {}", err);
                break
            }
        }
    }
}


fn fuzz(tid: i64, cmd_args: &Vec<String>) {

    let mut rand = rand::thread_rng();

    unsafe {
        let orig_input: Vec<u8> = input_files[rand::thread_rng().gen_range(0..input_files.len())].clone();
        let mut scratch_space: Vec<u8> = vec![0; orig_input.len()];
        let mut args: Vec<String> = Vec::new();
        
        let tmp_filename = format!("/Volumes/RAMDisk/ramstuff/.tmpFuzzFile{}", tid);
        args.push(tmp_filename);
        for i in 3..cmd_args.len() {
            args.push(cmd_args[i].clone());
        }

        loop {
            scratch_space.copy_from_slice(&orig_input);
            mutate::mutate(&mut rand, &mut scratch_space);
            // write temp fuzz file
            let tmp_filename = format!("/Volumes/RAMDisk/ramstuff/.tmpFuzzFile{}", tid);
            fs::write(&tmp_filename, &scratch_space).unwrap();

            match unsafe{ fork() } {
                Ok(ForkResult::Child) => {
                    run_child(&cmd_args[2], &args);
                }
                Ok(ForkResult::Parent {child}) => {
                    run_parent(child, &scratch_space);
                }
                Err(err) => {
                    panic!("[fuzz-{}] fork() failed: {}", tid, err);
                }
            }

            unsafe { COUNTER += 1 };
        }
    }
}

fn main() {

    let prog_args: Vec<String> = args().collect();
    if prog_args.len() == 1 {
        println!("Usage: {} <corpus folder> <command> [CMD ARG1] [CMD ARG2]... (input files will be placed last)", prog_args[0]);
        exit(1);
    }
		
		//fill_up_input_files(Path::new("/Users/esjay/fun/fuzz/targets/assetutil/crashes/"));
		fill_up_input_files(Path::new(&prog_args[1]));

    let mut threads = vec![];

    thread::spawn(|| {
        print_statistics();
    });

    println!("[*] Start fuzzing threads...");
    for i in 0..NTHREADS {
        //let tmp = prog_args[2].clone();
        let tmp = prog_args.clone();
        threads.push(thread::spawn(move|| {
            fuzz(i, &tmp);
        }));
    }

    for t in threads {
        let _ = t.join();
    }
}
