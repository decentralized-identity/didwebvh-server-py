"""Fast local avatar generator using SVG identicons."""

import hashlib
import base64
from typing import List, Tuple


def generate_avatar_svg(seed: str) -> str:
    """
    Generate a deterministic SVG identicon based on a seed.
    
    This creates a 5x5 grid pattern with vertical symmetry,
    similar to GitHub's identicons but as inline SVG data URI.
    
    Args:
        seed: The seed string (typically scid)
        
    Returns:
        Data URI string with inline SVG
    """
    # Hash the seed to get deterministic values
    hash_bytes = hashlib.sha256(seed.encode()).digest()
    
    # Extract color from first 3 bytes (RGB)
    r = hash_bytes[0]
    g = hash_bytes[1]
    b = hash_bytes[2]
    
    # Create a lighter background color
    bg_r = min(255, r + 100)
    bg_g = min(255, g + 100)
    bg_b = min(255, b + 100)
    
    # Generate 5x5 grid pattern (only need 15 values due to symmetry)
    # Use bytes 3-17 for the pattern
    grid = []
    for i in range(15):
        # Each byte represents whether a cell should be filled
        grid.append(hash_bytes[3 + i] % 2 == 0)
    
    # Build the SVG
    cell_size = 20
    size = 5 * cell_size
    
    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 {size} {size}">',
        f'<rect width="{size}" height="{size}" fill="rgb({bg_r},{bg_g},{bg_b})"/>'
    ]
    
    # Draw the pattern with vertical symmetry
    idx = 0
    for row in range(5):
        for col in range(3):  # Only first 3 columns (middle column and left side)
            if grid[idx]:
                x1 = col * cell_size
                y = row * cell_size
                # Draw left side
                svg_parts.append(
                    f'<rect x="{x1}" y="{y}" width="{cell_size}" height="{cell_size}" fill="rgb({r},{g},{b})"/>'
                )
                # Mirror to right side (symmetry)
                if col < 2:  # Don't mirror the middle column
                    x2 = (4 - col) * cell_size
                    svg_parts.append(
                        f'<rect x="{x2}" y="{y}" width="{cell_size}" height="{cell_size}" fill="rgb({r},{g},{b})"/>'
                    )
            idx += 1
    
    svg_parts.append('</svg>')
    svg_content = ''.join(svg_parts)
    
    # Return as base64 encoded data URI (more reliable than URL encoding)
    svg_bytes = svg_content.encode('utf-8')
    svg_base64 = base64.b64encode(svg_bytes).decode('ascii')
    return f"data:image/svg+xml;base64,{svg_base64}"


def generate_geometric_avatar(seed: str) -> str:
    """
    Generate a geometric pattern avatar (alternative style).
    
    Creates a more abstract pattern with circles and shapes.
    """
    hash_bytes = hashlib.sha256(seed.encode()).digest()
    
    # Colors
    r1, g1, b1 = hash_bytes[0], hash_bytes[1], hash_bytes[2]
    r2, g2, b2 = hash_bytes[3], hash_bytes[4], hash_bytes[5]
    
    # Background
    bg_r = min(255, (r1 + r2) // 2 + 80)
    bg_g = min(255, (g1 + g2) // 2 + 80)
    bg_b = min(255, (b1 + b2) // 2 + 80)
    
    size = 100
    svg_parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 {size} {size}">',
        f'<rect width="{size}" height="{size}" fill="rgb({bg_r},{bg_g},{bg_b})"/>'
    ]
    
    # Draw some circles based on hash
    num_circles = 3 + (hash_bytes[6] % 4)
    for i in range(num_circles):
        cx = (hash_bytes[7 + i * 3] % 80) + 10
        cy = (hash_bytes[8 + i * 3] % 80) + 10
        r = (hash_bytes[9 + i * 3] % 30) + 10
        opacity = 0.3 + (hash_bytes[10 + i * 3] % 50) / 100
        
        color = f"rgb({r1},{g1},{b1})" if i % 2 == 0 else f"rgb({r2},{g2},{b2})"
        svg_parts.append(
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{color}" opacity="{opacity:.2f}"/>'
        )
    
    svg_parts.append('</svg>')
    svg_content = ''.join(svg_parts)
    
    # Return as base64 encoded data URI (more reliable than URL encoding)
    svg_bytes = svg_content.encode('utf-8')
    svg_base64 = base64.b64encode(svg_bytes).decode('ascii')
    return f"data:image/svg+xml;base64,{svg_base64}"


def generate_avatar(seed: str, style: str = "identicon") -> str:
    """
    Generate an avatar based on seed.
    
    Args:
        seed: The seed string (typically scid)
        style: Avatar style - "identicon" or "geometric"
        
    Returns:
        Data URI string with inline SVG
    """
    if style == "geometric":
        return generate_geometric_avatar(seed)
    else:
        return generate_avatar_svg(seed)
