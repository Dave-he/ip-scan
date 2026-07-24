export const meta = {
  name: "ip-scan-deploy",
  description: "一键部署 ip-scan 到 sshtx 和 sshali 两台服务器：同步源码 → 并行编译 → 停旧进程 → 启动新扫描",
};

export default async function ({ args }) {
  const servers = [
    {
      name: "sshtx",
      host: "43.133.224.11",
      port: "2222",
      user: "root",
      remoteDir: "/root/ip-scan",
      target: args?.target || "43.133.224.0/24",
      ports: args?.ports || "22,80,443,8080,2222,888,9999,19090,20320",
      concurrency: args?.concurrency || "500",
      cpuCores: 2,
    },
    {
      name: "sshali",
      host: "39.103.188.33",
      port: "2222",
      user: "root",
      remoteDir: "/root/ip-scan",
      target: args?.target || "39.103.188.0/24",
      ports: args?.ports || "22,80,443,8080,2222,888,9999,19090,20320",
      concurrency: args?.concurrency || "1000",
      cpuCores: 4,
    },
  ];

  const sshBase = (s) => `ssh -p ${s.port} -o ConnectTimeout=10 -o StrictHostKeyChecking=no ${s.user}@${s.host}`;
  const rsyncBase = (s) => `rsync -avz --delete -e "ssh -p ${s.port} -o StrictHostKeyChecking=no"`;

  phase("Sync source code to servers");
  log("Rsync source files to both servers in parallel...");
  const syncResults = await parallel(
    servers.map((s) => () =>
      agent(
        `Run this bash command to sync the ip-scan project to ${s.name}:\n` +
        `${rsyncBase(s)} --exclude='target/' --exclude='.git/' --exclude='scan_results.db' --exclude='*.log' ` +
        `/Users/hyx/codespace/ip-scan/ ${s.user}@${s.host}:${s.remoteDir}/\n\n` +
        `Return: success or error message`,
        { label: `sync:${s.name}`, phase: "Sync source code to servers", subagent_type: "GeneralPurpose" }
      )
    )
  );
  const synced = syncResults.filter(Boolean);
  log(`Synced to ${synced.length}/${servers.length} servers`);

  phase("Build on servers");
  log("Starting cargo build --release on both servers in parallel...");
  const buildResults = await parallel(
    servers.map((s) => () =>
      agent(
        `Build ip-scan on ${s.name} server. Run these commands via SSH:\n\n` +
        `1. SSH command: ${sshBase(s)}\n` +
        `2. Run: export PATH=$HOME/.cargo/bin:$PATH && cd ${s.remoteDir} && cargo build --release 2>&1\n` +
        `3. Verify: ls ${s.remoteDir}/target/release/ip-scan\n\n` +
        `Return: build success or error message`,
        { label: `build:${s.name}`, phase: "Build on servers", subagent_type: "GeneralPurpose" }
      )
    )
  );
  const built = buildResults.filter(Boolean);
  log(`Built on ${built.length}/${servers.length} servers`);

  phase("Deploy and start scanning");
  log("Stopping old processes and starting new scans on both servers...");
  const deployResults = await parallel(
    servers.map((s) => () =>
      agent(
        `Deploy and start ip-scan on ${s.name} server. Run these commands via SSH:\n\n` +
        `SSH command: ${sshBase(s)}\n\n` +
        `Run the following commands (chained with &&):\n` +
        `1. Kill old process: pkill -f ip-scan || true\n` +
        `2. Wait: sleep 1\n` +
        `3. Remove old DB: rm -f ${s.remoteDir}/scan_results.db\n` +
        `4. Start scan (nohup):\n` +
        `   cd ${s.remoteDir} && nohup ${s.remoteDir}/target/release/ip-scan \\\n` +
        `     --api --ipv4 \\\n` +
        `     --target ${s.target} \\\n` +
        `     --ports ${s.ports} \\\n` +
        `     --timeout 500 \\\n` +
        `     --concurrency ${s.concurrency} \\\n` +
        `     --no-geo \\\n` +
        `     --database ${s.remoteDir}/scan_results.db \\\n` +
        `     > ${s.remoteDir}/scan.log 2>&1 &\n` +
        `5. Wait: sleep 3\n` +
        `6. Verify running: curl -s http://localhost:8080/api/v1/stats\n\n` +
        `Return: stats JSON or error message`,
        { label: `deploy:${s.name}`, phase: "Deploy and start scanning", subagent_type: "GeneralPurpose" }
      )
    )
  );
  const deployed = deployResults.filter(Boolean);
  log(`Deployed on ${deployed.length}/${servers.length} servers`);

  phase("Verify");
  log("Verifying both servers are accessible...");
  const verifyResults = await parallel(
    servers.map((s) => () =>
      agent(
        `Verify ip-scan is running on ${s.name}.\n\n` +
        `1. SSH: ${sshBase(s)}\n` +
        `2. Run: curl -s http://localhost:8080/api/v1/stats\n` +
        `3. Also check from outside: curl -s http://${s.host}:8080/api/v1/stats (may fail if firewall blocks)\n\n` +
        `Return: the stats JSON and whether the service is healthy`,
        { label: `verify:${s.name}`, phase: "Verify", subagent_type: "GeneralPurpose" }
      )
    )
  );

  const results = servers.map((s, i) => ({
    name: s.name,
    host: s.host,
    api: `http://${s.host}:8080`,
    sync: synced[i] ? "OK" : "FAIL",
    build: built[i] ? "OK" : "FAIL",
    deploy: deployed[i] ? "OK" : "FAIL",
    verify: verifyResults[i] || "UNKNOWN",
  }));

  return {
    summary: `Deployed ip-scan to ${deployed.length}/${servers.length} servers`,
    servers: results,
    usage: "Re-run with args: { target: 'x.x.x.x/24', ports: '22,80', concurrency: '500' } to customize",
  };
}
