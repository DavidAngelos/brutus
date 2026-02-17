//! Session management for non-NLA RDP connections.
//!
//! After the connector reaches the Connected state, a SessionHandle wraps
//! IronRDP's ActiveStage to drive the graphical session: processing server
//! frames, decoding screen updates, and sending keyboard input.

use ironrdp_connector::ConnectionResult;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_input::{Database as InputDatabase, MouseButton, MousePosition, Operation, Scancode};
use ironrdp_pdu::Action;
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageOutput};

// State constants returned to Go (must match Go session state constants)
#[allow(dead_code)]
pub const STATE_SESSION_READY: u32 = 20;
pub const STATE_FRAME_AVAILABLE: u32 = 21;
pub const STATE_INPUT_SENT: u32 = 22;
pub const STATE_SESSION_ERROR: u32 = 25;
pub const STATE_SESSION_NEED_SEND: u32 = 26;
pub const STATE_SESSION_NEED_RECV: u32 = 27;

/// Holds an active RDP session after the connector handshake completes.
///
/// The Go host drives this by:
/// 1. Calling `process_server_data()` with bytes received from the server
/// 2. Sending any response bytes back to the server
/// 3. Calling `send_key()` to inject keyboard input
/// 4. Calling `get_frame_rgba()` to read the decoded framebuffer
pub struct SessionHandle {
    active_stage: ActiveStage,
    image: DecodedImage,
    input_db: InputDatabase,
    width: u16,
    height: u16,
    frame_updated: bool,
}

impl SessionHandle {
    /// Create a new session from a completed connection result.
    pub fn new(
        connection_result: ConnectionResult,
        width: u16,
        height: u16,
    ) -> Result<Self, String> {
        let image = DecodedImage::new(PixelFormat::RgbA32, width, height);
        let active_stage = ActiveStage::new(connection_result);
        let input_db = InputDatabase::new();

        Ok(SessionHandle {
            active_stage,
            image,
            input_db,
            width,
            height,
            frame_updated: false,
        })
    }

    /// Process incoming server data. Returns (state_code, output_bytes_to_send).
    ///
    /// The first byte of input determines FastPath vs X224 framing via
    /// `Action::from_fp_output_header`.
    pub fn process_server_data(&mut self, input: &[u8]) -> (u32, Vec<u8>) {
        if input.is_empty() {
            return (STATE_SESSION_NEED_RECV, Vec::new());
        }

        // Determine action from first byte
        let action = match Action::from_fp_output_header(input[0]) {
            Ok(a) => a,
            Err(_) => {
                return (
                    STATE_SESSION_ERROR,
                    b"invalid frame action byte".to_vec(),
                );
            }
        };

        match self.active_stage.process(&mut self.image, action, input) {
            Ok(outputs) => {
                let mut response_bytes = Vec::new();
                for output_item in outputs {
                    match output_item {
                        ActiveStageOutput::ResponseFrame(frame) => {
                            response_bytes.extend_from_slice(&frame);
                        }
                        ActiveStageOutput::GraphicsUpdate(_) => {
                            self.frame_updated = true;
                        }
                        ActiveStageOutput::Terminate(reason) => {
                            return (
                                STATE_SESSION_ERROR,
                                format!("session terminated: {}", reason).into_bytes(),
                            );
                        }
                        ActiveStageOutput::DeactivateAll(_) => {
                            // Server-initiated deactivation-reactivation sequence.
                            // Not supported in this minimal session implementation.
                            return (
                                STATE_SESSION_ERROR,
                                b"server deactivation-reactivation not supported".to_vec(),
                            );
                        }
                        _ => {} // PointerDefault, PointerHidden, PointerPosition, PointerBitmap
                    }
                }

                if !response_bytes.is_empty() {
                    return (STATE_SESSION_NEED_SEND, response_bytes);
                }

                if self.frame_updated {
                    (STATE_FRAME_AVAILABLE, Vec::new())
                } else {
                    (STATE_SESSION_NEED_RECV, Vec::new())
                }
            }
            Err(e) => (
                STATE_SESSION_ERROR,
                format!("session error: {}", e).into_bytes(),
            ),
        }
    }

    /// Send a keyboard key press or release. Returns (state_code, output_bytes_to_send).
    pub fn send_key(&mut self, scancode: u16, pressed: bool) -> (u32, Vec<u8>) {
        let sc = Scancode::from_u16(scancode);
        let operation = if pressed {
            Operation::KeyPressed(sc)
        } else {
            Operation::KeyReleased(sc)
        };

        let events = self.input_db.apply(std::iter::once(operation));

        match self
            .active_stage
            .process_fastpath_input(&mut self.image, &events)
        {
            Ok(outputs) => {
                let mut response_bytes = Vec::new();
                for output_item in outputs {
                    if let ActiveStageOutput::ResponseFrame(frame) = output_item {
                        response_bytes.extend_from_slice(&frame);
                    }
                }
                (STATE_INPUT_SENT, response_bytes)
            }
            Err(e) => (
                STATE_SESSION_ERROR,
                format!("input error: {}", e).into_bytes(),
            ),
        }
    }

    /// Send a mouse event. Returns (state_code, output_bytes_to_send).
    ///
    /// button: 0=none (move only), 1=left, 2=right, 3=middle
    /// event_type: 0=move, 1=button press, 2=button release
    pub fn send_mouse(
        &mut self,
        x: u16,
        y: u16,
        button: u32,
        event_type: u32,
    ) -> (u32, Vec<u8>) {
        let mut operations = vec![Operation::MouseMove(MousePosition { x, y })];

        let mouse_btn = match button {
            1 => Some(MouseButton::Left),
            2 => Some(MouseButton::Right),
            3 => Some(MouseButton::Middle),
            _ => None,
        };

        if let Some(btn) = mouse_btn {
            match event_type {
                1 => operations.push(Operation::MouseButtonPressed(btn)),
                2 => operations.push(Operation::MouseButtonReleased(btn)),
                _ => {} // move only
            }
        }

        let events = self.input_db.apply(operations.into_iter());

        match self
            .active_stage
            .process_fastpath_input(&mut self.image, &events)
        {
            Ok(outputs) => {
                let mut response_bytes = Vec::new();
                for output_item in outputs {
                    if let ActiveStageOutput::ResponseFrame(frame) = output_item {
                        response_bytes.extend_from_slice(&frame);
                    }
                }
                (STATE_INPUT_SENT, response_bytes)
            }
            Err(e) => (
                STATE_SESSION_ERROR,
                format!("mouse input error: {}", e).into_bytes(),
            ),
        }
    }

    /// Get the current framebuffer as RGBA pixel data.
    pub fn get_frame_rgba(&self) -> &[u8] {
        self.image.data()
    }

    /// Check and reset the frame-updated flag.
    #[allow(dead_code)]
    pub fn take_frame_updated(&mut self) -> bool {
        let was_updated = self.frame_updated;
        self.frame_updated = false;
        was_updated
    }

    pub fn width(&self) -> u16 {
        self.width
    }

    pub fn height(&self) -> u16 {
        self.height
    }
}
