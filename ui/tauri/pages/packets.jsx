export default function PacketsView({ packets }) {
  return (
    <div>
      <h2>Packets</h2>
      <ul>
        {packets.map((p, i) => (
          <li key={i}>
            {p.ip?.src_ip} → {p.ip?.dst_ip} [{p.transport?.type}]
          </li>
        ))}
      </ul>
    </div>
  );
}
