export default function IpDetails({ ip }) {
  return (
    <div>
      <h2>IP Details</h2>
      <p>{ip.ip}</p>
      <p>{ip.country}</p>
      <p>Score: {ip.score}</p>
    </div>
  );
}
