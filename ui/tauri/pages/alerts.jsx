export default function Alerts({ alerts }) {
  return (
    <div>
      <h2>Alerts</h2>
      {alerts.map((a, i) => (
        <div key={i} style={{ color: "red" }}>
          {a.message}
        </div>
      ))}
    </div>
  );
}
