import pyotp
import qrcode
import io
import base64

def generate_secret():
    """Generate a new TOTP secret for a user"""
    return pyotp.random_base32()

def get_qr_code(username, secret):
    """Generate QR code as base64 image for Google Authenticator"""
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name="CloudShield"
    )
    
    qr = qrcode.QRCode(version=1, box_size=8, border=2)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64 to embed in HTML
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"

def verify_otp(secret, otp_code):
    """Verify the 6-digit OTP code"""
    if not secret or not otp_code:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(otp_code, valid_window=1)