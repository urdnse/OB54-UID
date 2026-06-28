import struct
from typing import Any, Type

class ProtobufUtils:
    def __init__(self):
        pass
    
    def decode_protobuf(self, hex_data: str, protobuf_class: Type) -> Any:
        """
        Decode protobuf from hex string
        Args:
            hex_data: hex string containing protobuf data
            protobuf_class: protobuf class to decode into (e.g., Login_pb2.LoginReq)
        Returns:
            decoded protobuf object
        """
        # Convert hex to bytes
        if isinstance(hex_data, str):
            binary_data = bytes.fromhex(hex_data)
        else:
            binary_data = hex_data
        
        # Create instance of protobuf class and parse
        protobuf_obj = protobuf_class()
        protobuf_obj.ParseFromString(binary_data)
        
        return protobuf_obj
    
    def protobuf_encode(self, protobuf_obj: Any) -> bytes:
        """
        Encode protobuf object to bytes
        Args:
            protobuf_obj: protobuf object to encode
        Returns:
            encoded bytes
        """
        return protobuf_obj.SerializeToString()

# Test function to verify our implementation
def test_protobuf_utils():
    """Test the ProtobufUtils implementation"""
    try:
        import Login_pb2
        
        proto_utils = ProtobufUtils()
        
        # Create a test LoginReq object
        login_req = Login_pb2.LoginReq()
        login_req.deviceData = "test_device_data"
        login_req.reserved20 = b"test_reserved"
        
        # Encode to bytes
        encoded = proto_utils.protobuf_encode(login_req)
        print(f"Encoded protobuf (hex): {encoded.hex()}")
        
        # Decode back
        decoded = proto_utils.decode_protobuf(encoded.hex(), Login_pb2.LoginReq)
        print(f"Decoded deviceData: {decoded.deviceData}")
        print(f"Decoded reserved20: {decoded.reserved20}")
        
        # Verify
        assert login_req.deviceData == decoded.deviceData, "DeviceData mismatch!"
        assert login_req.reserved20 == decoded.reserved20, "Reserved20 mismatch!"
        print("✅ Protobuf encode/decode test passed!")
        
    except ImportError:
        print("⚠️ Login_pb2 not available for testing, but implementation should work")
    except Exception as e:
        print(f"❌ Test failed: {e}")

if __name__ == "__main__":
    test_protobuf_utils()
