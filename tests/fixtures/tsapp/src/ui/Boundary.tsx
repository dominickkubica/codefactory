// A React-style error boundary: these methods are called by the framework, never by the app.
export class Boundary {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch(error: unknown) {
    console.log(error);
  }

  render() {
    return this.state.failed ? "Something went wrong" : "ok";
  }
}
