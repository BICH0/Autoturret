use std::{
        net::{TcpListener,TcpStream,SocketAddr,IpAddr},
        io::{prelude::*, BufReader,stdout},
        process::Command,
        env,
        str::FromStr,
        future::{Future},
        fs::File,
        path::Path,
        thread,
    };
use reqwest::{Response,Error};
use dns_lookup::lookup_host;
use serde_json::Value;
use futures_util::StreamExt;
use filepath::FilePath;
use rusqlite::{Connection,CachedStatement};
use blake3;
use daemonize::Daemonize;
use colored::{ColoredString,Colorize};
use std::collections::HashMap;

#[derive(Debug)]
struct Package{
    name: String,
    rversion: String,
    deps: Option<String>,
}

const PORT:u16 = 1407;
const LOGS:&str = "/var/log/autoturret";
fn line_result(text:&str,mode:&str,prev:Option<usize>,end:bool) ->usize{
    let mode:ColoredString= match mode{
        "ok" => "[OK] ".green(),
        "warn" => "[WARN] ".yellow(),
        "err" => "[ERROR] ".red(),
        "info" => "[INFO] ".purple(),
        "add" => "[+] ".green(),
        "rem" => "[-] ".red(),
        _ => "".white()
    };
    let prev:usize=match prev{
        Some(n) => {
            if n < text.len(){
                n
            }else{
                n-text.len()
            }
        },
        Non => 0,
    };
    let mut text:String=text.to_owned();
    for c in 1..prev{
        text=text+" ";
    }
    let mut line = format!("{}{}",mode,text);
    if prev != 0{
        line="\r".to_owned()+&line;
    }
    print!("{}",line);
    if end{
        println!("");
    }
    return line.len();
}
async fn handle_input(mode:&str){
    /*
        Añadir opcion para actualizar, mirar los mirrors online, sincronizar mirrors
    */
    match mode{
        "master" => {
            loop{
                let mut user_input = String::new();
                let stdin = std::io::stdin();
                match stdin.read_line(&mut user_input){
                    Ok(input) =>{
                        println!("Master send");
                        tcp_send("SYN","mirrors.confugiradores.es:1407".to_string()).await.unwrap();
                    },
                    Err(_) => ()
                }
            }
        },
        "slave" => {
            loop{
                let mut user_input = String::new();
                let stdin = std::io::stdin();
                match stdin.read_line(&mut user_input){
                    Ok(input) =>{
                        println!("Truers");
                        tcp_send("SYN","127.0.0.1:1407".to_string()).await;
                    },
                    Err(_) => ()
                }
            }
        },
        _ => ()
    }
}
async fn get_file(fname:&str,url:&str) -> Result<File,String>{
    match reqwest::get(format!("http://{}/{}",url,fname)).await{
        Ok(res) => {
            if res.status().as_str() == "404"{
               return Err("File not found on the server".to_string())
            }
            let mut file = std::fs::File::create(&fname).unwrap();
            let mut stream = res.bytes_stream();
            while let Some(item) = stream.next().await {
                let chunk = item.expect("Error while downloading file");
                file.write_all(&chunk).expect("Error while writing to file");
            }
            Ok(file)
        },
        Err(e) => {
            Err(format!("Unable to connect to the server {:?}",e))
        }
    }
}
async fn hash_check(file:File,mirror:String) -> Result<File,String>{
    let bfile = format!("{}.b3",file.path().unwrap().to_str().unwrap().split("/").last().unwrap().split(".").nth(0).unwrap().to_owned());
    match get_file(&bfile,&mirror).await{
        Ok(_) => {
            match File::open(file.path().unwrap()) {
                Ok(mut ofile) => {
                    let mut bytes:Vec<u8> = Vec::new();
                    ofile.read_to_end(&mut bytes);
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(&bytes);
                    let hash = hasher.finalize();
                    let mut rhash:String = String::new();
                    File::open(bfile).expect("Unable to open checksum file").read_to_string(&mut rhash);//TODO Handle err
                    if hash.to_string().eq(rhash.split(" ").collect::<Vec<_>>()[0]){
                        return Ok(file)
                    }
                    else{
                        return Err("Hash doesnt match, file may be corrupted".to_string());
                    }
                },
                Err(_) => {
                    return Err("Unable to open hash file".to_string());
                }
        
            }
        },
        Err(e) => return Err(e),
    }
}
async fn file_download(fname:&str,mirror:Result<&str,&Vec<serde_json::Map<std::string::String, Value>>>) -> Result<File,String>{
    let fserver:&str;
    let mut lastline:usize= line_result(format!("Downloading {}",fname).as_str(),"",None,false);
    let file:Result<File,String> = match mirror {
        Ok(server) =>{
            fserver=server;
            Ok(get_file(fname,server).await.unwrap())
        },
        Err(servers) =>{
            if servers.len() == 0{
                return Err("No servers available".to_string())
            }
            let mut x = 0;
            loop{
                let server = servers[x]["name"].as_str().unwrap();
                match get_file(fname,server).await{
                    Ok(file) => {
                        fserver=server;
                        break Ok(file)
                    },
                    Err(_) => x+=1,
                }
            }
        }
    };
    match file{
        Ok(file) => {
            lastline=line_result("Verifying file integrity","",Some(lastline),false);
            match hash_check(file,fserver.to_string()).await{
                Ok(file) => {
                    line_result("File integrity verified","ok",Some(lastline),true);
                    return Ok(file)
                },
                Err(e) => {
                    line_result("Failed to verify file integrity","err",Some(lastline),true);
                    return Err(e)
                },
            }
        },
        Err(e) =>{
            println!("{}",e);
            return Err(e)
        }
    }
}
async fn sync_db(mirrors:Result<&str,&Vec<serde_json::Map<std::string::String, Value>>>) -> Result<(),String>{
    match file_download("eoka.db",mirrors).await{
        Ok(file) => {
            line_result("DB downloaded","ok",None,true);
            let conn = Connection::open("./eoka.db").unwrap();//TODO Cambiar a archivo de configuracion
            let mut stmt = conn.prepare_cached("SELECT name,rversion,deps FROM packages").unwrap();
            let mut packages:HashMap<String,Package> = HashMap::new();
            let rows = stmt.query_map([], |row| {
                Ok(Package{
                    name: row.get(0)?,
                    rversion: row.get(1)?,
                    deps: row.get(2)?,
                })
            }).unwrap();
            for package in rows{
                let package = package.unwrap();
                packages.insert(package.name.clone(),package);
            }
            // println!("{}",packages.len());
            for (name,package) in packages{
                println!("Pack {} - {:?}",name,package);
                // if package.rversion != 
            }
            //TODO Comprobar la version de cada paquete y si hay alguno distinto actualizarlo
            /*
            for package in db{
                if lversion != rversion{
                    file_download(file,mirror);
                }
            }
            */
        },
        Err(e) =>{
            line_result("","err",None,true);
            return Err(e);
        }
    }
    Ok(())

}
async fn master_handler(listener:TcpListener,mirrors:&mut Vec<serde_json::Map<std::string::String, Value>>){
    for stream in listener.incoming(){
        match handle_connection(stream.unwrap()){
            Ok(stream) =>{
                let host:Vec<&str> = stream[1].split(",").collect();
                let method:&str = stream[0].split("/").nth(1).unwrap();
                match method{
                    "SYN" => {
                        println!("Recieved sync from {}",host[1]);
                        sync_db(Ok(host[1].split(":").nth(0).unwrap())).await.unwrap();
                        /*
                            TODO NOTIFICAR A TODOS LOS ESCLAVOS, DE ESTO SE ENCARGA EL MASTER QUE HAYA EMITIDO EL SYN
                            ASI NOS AHORRAMOS CARGA EN LA RED
                        */
                    },
                    "CONN" => {
                        println!("Adding client to active");
                        let socket:Vec<&str> = host[1].split(":").collect();
                        println!("{:?}",host);
                        let entry:serde_json::Map<std::string::String, Value>={
                            let mut map = serde_json::Map::new();
                            map.insert("name".to_string(),socket[0].into());
                            map.insert("port".to_string(),socket[1].into());    
                            map.insert("role".to_string(),"slave".into());
                            map
                        };
                        mirrors.push(entry);
                    },
                    _ => {
                        println!("Invalid method, ignoring");
                    }
                }
            },
            Err(e) => {
                println!(" {}",e);
            }
        }
    }

}
async fn slave_handler(listener:TcpListener,mirrors:&Vec<serde_json::Map<std::string::String, Value>>){
    for stream in listener.incoming(){
        match handle_connection(stream.unwrap()){
            Ok(stream) =>{
                let host:Vec<&str> = stream[1].split(",").collect();
                let method:&str = stream[0].split("/").nth(1).unwrap();
                match method{
                    "SYN" => {
                        println!("Recieved sync, downloading DB");
                        get_file("eoka.db","mirror.confugiradores.es").await.unwrap();
                        sync_db(Err(mirrors)).await;
                    },
                    _ => {
                        println!("Invalid method, ignoring"); 
                    }
                }
            },
            Err(e) => {
                println!("{}",e);
            }
        }
    }
}

fn handle_connection(mut stream:TcpStream) -> Result<Vec<String>,String>{
    let buf_reader = BufReader::new(&mut stream);
    let request:Vec<_> = buf_reader
        .lines()
        .map(|result| result.unwrap())
        .take_while(|line| !line.is_empty())
        .collect();
    match request[0].split("/").nth(0){
        Some(req) => {
            if req == "Eoka-Autoturret"{
                println!("{:?}", request);
                let host:Vec<&str> = request[1].split(",").collect();
                let ips:Vec<std::net::IpAddr> = lookup_host(&host[1].split(":").nth(0).unwrap()).unwrap();
                let valid_mirror:bool = {
                    let mut res:bool = false;
                    for ip in &ips{
                        if ip == &host[0].parse::<IpAddr>().unwrap(){
                            res=true;
                            break;
                        }
                    }
                    res
                };
                if valid_mirror{
                    return Ok(request)
                }else{
                    return Err(format!("Domain doesn't match DNS IP\n Expected {} but got {}",ips[0],host[0]));
                }
            }
        },
        None => (),
    }
    return Err(format!("Invalid protocol -> {}",&request[0]));
}
async fn tcp_send(method:&str,server:String) -> Result<String,String>{
    match TcpStream::connect(&server){
        Ok(mut stream) => {
            match public_ip::addr_v4().await{
                Some(res) => {
                    stream.write(format!("Eoka-Autoturret/{}\n{},{}",method,&res.to_string(),"mirror.confugiradores.es:1407").as_bytes()).unwrap();//TODO modificar mirror.confugiradores para que lo coja de algun sitio
                    return Ok(format!("Connected to mirror at {}",server))
                },
                None => {
                    return Err("Error fetching your public IP".to_string())
                }
            }
        },
        Err(e) => return Err(format!("Server refused the connection: \n{:?}",e))
    }
}
#[tokio::main]
async fn main() {
    let mode:&str;
    let mut daemon:bool = false;
    let mut port:u16 = PORT;
    let args:Vec<String> = env::args().collect::<Vec<String>>();
    match args[1].as_str(){
        "master" => mode="master",
        "slave" => {
            mode="slave";
            port=PORT+1;
        },
        "update" => {
            println!("Sending local updates to all mirrors...");
            tcp_send("UPDATE","localhost:1407".to_string()).await.unwrap();
            //for master in masters
            //for slave in slaves
            return
        }
        e => {
            println!("Invalid mode, available modes: master, slave, update");
            return
        }
    }
    if args.len() >= 2{
        let mut x = 2;
        while x<args.len(){
            match args[x].as_str(){
                "--daemon" => daemon=true,
                "--port" => {
                    port={
                        match args[x+1].parse::<u16>(){
                            Ok(n) => n,
                            Err(e) => {
                                println!("Invalid port {}",e);
                                return
                            }
                        }
                    };
                    x+=1;
                },
                e => println!("Unknown argument {}",e),
            }
            x+=1;
        }
    }
    println!("Syncing mirrors-----------");
    let json:Result<File,String> = file_download("mirrors.json",Ok("mirror.confugiradores.es")).await;
    let mut mirrors:Vec<serde_json::Map<std::string::String, Value>>=Vec::new();
    match json{
        Ok(file) => {
            let file = file.path();
            let data = std::fs::read_to_string(file.unwrap()).expect("Unable to read file");
            let res:serde_json::Value = serde_json::from_str(&data).expect("Unable to parse");
            for server in res["servers"].as_array().unwrap(){
                let server = server.as_object().unwrap();
                mirrors.push(server.clone());
            }
            line_result("All mirrors synced","ok",None,true);
        },
        Err(e) => {
            line_result("Unable to sync mirrors","ok",None,true);
            println!("{}",e);
            return
        },
    }
    println!("   {} mirrors loaded",&mirrors.len());
    println!("--------------------------");
    let listener:TcpListener;
    let mut lastline:usize=line_result(format!("Starting autoturret on localhost:{}",port).as_str(),"",None,false);
    let listener:TcpListener = match TcpListener::bind(format!("0.0.0.0:{}",port)){
        Ok(lis) =>{
            line_result(format!("Autoturret started at localhost:{}",port).as_str(),"ok",Some(lastline),true);
            lis
        },
        Err(_) =>{
            line_result(format!("Unable to start autoturret, port {} is already in use.",&PORT).as_str(),"err",Some(lastline),true);
            return
        }
    };
    //Dar la opcion de usar --client --server
    if daemon{
        println!("Daemonizing autoturret");
        match std::fs::create_dir_all(LOGS){
            Ok(_)=>(),
            Err(e)=>{
                println!("{}",e);
                return
            }
        }
        let stdout = File::create(format!("{}/autoturret.log",LOGS)).unwrap();
        let stderr = File::create(format!("{}/autoturret.err",LOGS)).unwrap();
        let daemonize = Daemonize::new()
            .pid_file("/tmp/autoturret.pid") // Every method except `new` and `start`
            .chown_pid_file(true)      // is optional, see `Daemonize` documentation
            .working_directory("/tmp") // for default behaviour.
            .user("nobody")
            .group("daemon") // Group name
            .umask(0o777)    // Set umask, `0o027` by default.
            .stdout(stdout)  // Redirect stdout to `/tmp/daemon.out`.
            .stderr(stderr);  // Redirect stderr to `/tmp/daemon.err`.
    
        match daemonize.start() {
            Ok(_) => println!("Success, daemonized"),
            Err(e) => eprintln!("Error, {}", e),
        }
    }
    match mode{
        "master" => {
            tokio::task::spawn(async {handle_input(mode).await});
            master_handler(listener,&mut mirrors).await;
        },
        "slave" => {
            println!("Connecting with masters...");
            for x in 0..mirrors.len(){
                println!("Server {}:{} with role {}",&mirrors[x]["name"],&mirrors[x]["port"],&mirrors[x]["role"]);
                match tcp_send("CONN",format!("{}:{}",&mirrors[x]["name"].as_str().unwrap(),&mirrors[x]["port"])).await{
                    Ok(msg) => println!("{}",msg),
                    Err(err) => {
                        let index = mirrors.iter().position(|y| *y == mirrors[x]).unwrap();
                        mirrors.remove(index);
                        println!("{}",err);
                    }
                }
            }
            match sync_db(Err(&mirrors)).await{
                Ok(_) => {
                    tokio::task::spawn(async {handle_input(mode).await});
                    ()
                },
                Err(e) => {
                    line_result(&e,"err",Some(0),true);
                    return
                }
            }
            slave_handler(listener,&mirrors).await;
        }
        _ => {
            println!("Unknown mode use autoturret -h");
            return
        }
    }
}
