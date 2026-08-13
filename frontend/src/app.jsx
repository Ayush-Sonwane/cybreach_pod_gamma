import { useEffect, useState } from "react";

const API = "/api/v2/webhook";

const emptyConnector = {
  id: "",
  name: "",
  secret: "",
  hmac_enabled: false,
  is_active: true
};

function App() {
  const [connector, setConnector] = useState(emptyConnector);
  const [connectors, setConnectors] = useState([]);
  const [health, setHealth] = useState(null);

  const [loading, setLoading] = useState(false);
  const [loadingData, setLoadingData] = useState(true);

  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const updateField = (field, value) => {
    setConnector((current) => ({
      ...current,
      [field]: value
    }));

    setMessage("");
    setError("");
  };

  const loadConnectors = async () => {
    const response = await fetch(`${API}/connectors`);

    if (!response.ok) {
      throw new Error(
        `Failed to load connectors: ${response.status}`
      );
    }

    const data = await response.json();

    setConnectors(
      Array.isArray(data)
        ? data
        : data.connectors || []
    );
  };

  const loadHealth = async () => {
    const response = await fetch(`${API}/health`);

    if (!response.ok) {
      throw new Error(
        `Failed to load health: ${response.status}`
      );
    }

    const data = await response.json();

    setHealth(data);
  };

  const loadData = async () => {
    setLoadingData(true);
    setError("");

    try {
      await Promise.all([
        loadConnectors(),
        loadHealth()
      ]);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingData(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const saveConnector = async (event) => {
    event.preventDefault();

    setLoading(true);
    setMessage("");
    setError("");

    if (!connector.id.trim()) {
      setError("Connector ID is required.");
      setLoading(false);
      return;
    }

    if (!connector.name.trim()) {
      setError("Connector name is required.");
      setLoading(false);
      return;
    }

    if (!connector.secret.trim()) {
      setError("Connector secret is required.");
      setLoading(false);
      return;
    }

    try {
      const response = await fetch(
        `${API}/connectors`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            id: connector.id.trim(),
            name: connector.name.trim(),
            secret: connector.secret,
            hmac_enabled: connector.hmac_enabled,
            is_active: connector.is_active
          })
        }
      );

      const data = await response.json();

      if (!response.ok) {
        let detail = "Unable to create connector.";

        if (typeof data.detail === "string") {
          detail = data.detail;
        } else if (Array.isArray(data.detail)) {
          detail = data.detail
            .map((item) => item.msg)
            .join(", ");
        } else if (
          data.detail &&
          typeof data.detail.message === "string"
        ) {
          detail = data.detail.message;
        }

        if (response.status === 409) {
          detail =
            "Connector ID already exists. Please use a different ID.";
        }

        throw new Error(detail);
      }

      setMessage(
        "Webhook connector created successfully."
      );

      setConnector({
        ...emptyConnector
      });

      await loadData();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setConnector({
      ...emptyConnector
    });

    setMessage("");
    setError("");
  };

  return (
    <div className="app">

      {/* HEADER */}

      <header className="topbar">

        <div>
          <h1>Pod Gamma</h1>
          <p>Generic Webhook Connector</p>
        </div>

        <div className="connection-status">
          <span />
          Backend Connected
        </div>

      </header>


      <main className="container">

        {/* INTRO */}

        <section className="intro">

          <p className="eyebrow">
            CONNECTOR CONFIGURATION
          </p>

          <h2>
            Generic Webhook Connector
          </h2>

          <p>
            Configure a webhook connector for
            custom SIEM solutions.
          </p>

        </section>


        {/* CONNECTOR CONFIGURATION */}

        <section className="card">

          <div className="card-header">

            <div>

              <h3>
                Connector configuration
              </h3>

              <p>
                Configure the connector according
                to the webhook service API.
              </p>

            </div>

          </div>


          <form onSubmit={saveConnector}>

            <div className="form-grid">

              {/* CONNECTOR ID */}

              <div className="field">

                <label htmlFor="connector-id">
                  Connector ID
                </label>

                <input
                  id="connector-id"
                  type="text"
                  value={connector.id}
                  onChange={(event) =>
                    updateField(
                      "id",
                      event.target.value
                    )
                  }
                  placeholder="Enter connector ID"
                />

              </div>


              {/* CONNECTOR NAME */}

              <div className="field">

                <label htmlFor="connector-name">
                  Connector Name
                </label>

                <input
                  id="connector-name"
                  type="text"
                  value={connector.name}
                  onChange={(event) =>
                    updateField(
                      "name",
                      event.target.value
                    )
                  }
                  placeholder="Enter connector name"
                />

              </div>


              {/* SECRET */}

              <div className="field full">

                <label htmlFor="connector-secret">
                  Connector Secret
                </label>

                <input
                  id="connector-secret"
                  type="password"
                  value={connector.secret}
                  onChange={(event) =>
                    updateField(
                      "secret",
                      event.target.value
                    )
                  }
                  placeholder="Enter connector secret"
                />

                <small>
                  The secret is used to authenticate
                  webhook requests.
                </small>

              </div>

            </div>


            {/* HMAC */}

            <div className="toggle">

              <div>

                <strong>
                  Enable HMAC authentication
                </strong>

                <span>
                  Enable HMAC-SHA256 signature
                  verification for this connector.
                </span>

              </div>

              <button
                type="button"
                className={
                  connector.hmac_enabled
                    ? "switch active"
                    : "switch"
                }
                onClick={() =>
                  updateField(
                    "hmac_enabled",
                    !connector.hmac_enabled
                  )
                }
                aria-label="Toggle HMAC"
              >
                <span />
              </button>

            </div>


            {/* ACTIVE */}

            <div className="toggle">

              <div>

                <strong>
                  Active connector
                </strong>

                <span>
                  Allow this connector to receive
                  webhook events.
                </span>

              </div>

              <button
                type="button"
                className={
                  connector.is_active
                    ? "switch active"
                    : "switch"
                }
                onClick={() =>
                  updateField(
                    "is_active",
                    !connector.is_active
                  )
                }
                aria-label="Toggle connector"
              >
                <span />
              </button>

            </div>


            {/* MESSAGES */}

            {message && (
              <div className="success">
                {message}
              </div>
            )}

            {error && (
              <div className="error">
                {error}
              </div>
            )}


            {/* ACTIONS */}

            <div className="actions">

              <button
                type="button"
                className="secondary"
                onClick={resetForm}
              >
                Reset
              </button>

              <button
                type="submit"
                className="primary"
                disabled={loading}
              >
                {loading
                  ? "Creating..."
                  : "Create connector"}
              </button>

            </div>

          </form>

        </section>


        {/* REGISTERED CONNECTORS */}

        <section className="card">

          <div className="card-header">

            <div>

              <h3>
                Registered connectors
              </h3>

              <p>
                Connectors registered with the
                Generic Webhook service.
              </p>

            </div>

            <button
              className="refresh"
              onClick={loadData}
            >
              Refresh
            </button>

          </div>


          {loadingData ? (

            <div className="empty">
              Loading connectors...
            </div>

          ) : connectors.length === 0 ? (

            <div className="empty">
              No connectors registered yet.
            </div>

          ) : (

            <div className="connector-list">

              {connectors.map((item, index) => (

                <div
                  className="connector-row"
                  key={item.id || index}
                >

                  <div>

                    <strong>
                      {item.name || item.id}
                    </strong>

                    <span>
                      ID: {item.id}
                    </span>

                  </div>

                  <div>

                    <span
                      className={
                        item.is_active
                          ? "badge enabled"
                          : "badge disabled"
                      }
                    >
                      {item.is_active
                        ? "Active"
                        : "Inactive"}
                    </span>

                  </div>

                </div>

              ))}

            </div>

          )}

        </section>


        {/* WEBHOOK HEALTH */}

        <section className="card">

          <div className="card-header">

            <div>

              <h3>
                Webhook health
              </h3>

              <p>
                Health information from the
                Generic Webhook service.
              </p>

            </div>

            <button
              className="refresh"
              onClick={loadData}
            >
              Refresh
            </button>

          </div>


          {health === null ? (

            <div className="empty">
              Loading health information...
            </div>

          ) : !health.connectors ||
            health.connectors.length === 0 ? (

            <div className="empty">
              No webhook activity recorded yet.
            </div>

          ) : (

            <div className="health-list">

              {health.connectors.map((item) => (

                <div
                  className="health-item"
                  key={item.connector_id}
                >

                  {/* HEALTH HEADER */}

                  <div className="health-title">

                    <div>

                      <strong>
                        {item.connector_id}
                      </strong>

                      <span>
                        Last status:{" "}
                        {item.last_status ||
                          "unknown"}
                      </span>

                    </div>

                    <span
                      className={
                        item.last_status === "valid"
                          ? "badge enabled"
                          : "badge disabled"
                      }
                    >
                      {item.last_status ||
                        "unknown"}
                    </span>

                  </div>


                  {/* HEALTH METRICS */}

                  <div className="health-grid">

                    <div className="health-stat">

                      <span>
                        Delivered
                      </span>

                      <strong>
                        {item.delivered}
                      </strong>

                    </div>


                    <div className="health-stat">

                      <span>
                        Valid
                      </span>

                      <strong>
                        {item.valid_count}
                      </strong>

                    </div>


                    <div className="health-stat">

                      <span>
                        Invalid
                      </span>

                      <strong>
                        {item.invalid_count}
                      </strong>

                    </div>


                    <div className="health-stat">

                      <span>
                        Auth failures
                      </span>

                      <strong>
                        {item.auth_failures}
                      </strong>

                    </div>


                    <div className="health-stat">

                      <span>
                        DLQ
                      </span>

                      <strong>
                        {item.dlq_count}
                      </strong>

                    </div>


                    <div className="health-stat">

                      <span>
                        Average latency
                      </span>

                      <strong>
                        {item.avg_latency_ms} ms
                      </strong>

                    </div>

                  </div>


                  {/* LAST ACTIVITY */}

                  <div className="health-details">

                    <div>

                      <span>
                        Last seen
                      </span>

                      <strong>
                        {item.last_seen ||
                          "N/A"}
                      </strong>

                    </div>


                    <div>

                      <span>
                        Last error
                      </span>

                      <strong>
                        {item.last_error ||
                          "None"}
                      </strong>

                    </div>

                  </div>

                </div>

              ))}

            </div>

          )}

        </section>

      </main>

    </div>
  );
}

export default App;