"""
Simulated Network Controller for Aegis-Gate.
Provides stateful VLAN and IP allocation to authorized devices.
"""

import ipaddress
import logging
from db.database import get_db

logger = logging.getLogger(__name__)

class NetworkAllocationError(Exception):
    pass

class SimulatedNetworkController:
    VLAN_GUEST = 100
    VLAN_USER = 200
    VLAN_ADMIN = 300
    
    IP_RANGE_START = "10.0.0.100"
    IP_RANGE_END = "10.0.0.254"

    @classmethod
    def _int_to_ip(cls, ip_int):
        return str(ipaddress.IPv4Address(ip_int))

    @classmethod
    def _ip_to_int(cls, ip_str):
        return int(ipaddress.IPv4Address(ip_str))

    @classmethod
    def allocate_network(cls, session_id: int, user_id: int, device_id: int, is_admin: bool) -> dict:
        """
        Allocate a VLAN and unique IP address for a new session.
        Uses database transaction to prevent race conditions.
        """
        vlan = cls.VLAN_ADMIN if is_admin else cls.VLAN_USER
        
        conn = get_db()
        try:
            # Enforce transaction (SQLite EXCLUSIVE lock)
            conn.execute("BEGIN EXCLUSIVE")
            
            # Check if session already has an allocation
            existing = conn.execute(
                "SELECT * FROM network_allocations WHERE session_id = ? AND status = 'allocated'",
                (session_id,)
            ).fetchone()
            if existing:
                conn.execute("ROLLBACK")
                return dict(existing)
            
            # Get currently allocated IPs
            allocated_ips = [
                row["ip_address"] for row in conn.execute(
                    "SELECT ip_address FROM network_allocations WHERE status = 'allocated'"
                ).fetchall()
            ]
            
            # Find next available IP
            start_int = cls._ip_to_int(cls.IP_RANGE_START)
            end_int = cls._ip_to_int(cls.IP_RANGE_END)
            allocated_ints = {cls._ip_to_int(ip) for ip in allocated_ips}
            
            new_ip = None
            for ip_int in range(start_int, end_int + 1):
                if ip_int not in allocated_ints:
                    new_ip = cls._int_to_ip(ip_int)
                    break
                    
            if not new_ip:
                conn.execute("ROLLBACK")
                raise NetworkAllocationError("IP pool exhausted.")
            
            # Record allocation
            conn.execute(
                """
                INSERT INTO network_allocations (session_id, user_id, device_id, vlan_id, ip_address)
                VALUES (?, ?, ?, ?, ?)
                """,
                (session_id, user_id, device_id, vlan, new_ip)
            )
            conn.commit()
            
            logger.info(f"Allocated IP {new_ip} on VLAN {vlan} for session {session_id}")
            return {
                "session_id": session_id,
                "vlan_id": vlan,
                "ip_address": new_ip,
                "status": "allocated"
            }
        except Exception as e:
            conn.execute("ROLLBACK")
            raise NetworkAllocationError(f"Network allocation failed: {e}")
        finally:
            conn.close()

    @classmethod
    def release_network(cls, session_id: int):
        """Release the network allocation for a terminated session."""
        conn = get_db()
        try:
            conn.execute("BEGIN EXCLUSIVE")
            conn.execute(
                """
                UPDATE network_allocations 
                SET status = 'released', released_at = datetime('now')
                WHERE session_id = ? AND status = 'allocated'
                """,
                (session_id,)
            )
            conn.commit()
            logger.info(f"Released network allocation for session {session_id}")
        except Exception as e:
            conn.execute("ROLLBACK")
            logger.error(f"Failed to release network: {e}")
        finally:
            conn.close()
