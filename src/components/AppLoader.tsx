import type { FC } from "react";
import "../styles/loader.css";

const AppLoader: FC = (): JSX.Element => {
  return (
    <div className="app-loader" role="status" aria-live="polite" aria-label="Loading application">
      <div className="app-loader-mark" />
      <div className="app-loader-text">Connecting to ChatNext</div>
    </div>
  );
};

export default AppLoader;
