from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import PyPDF2
import geopy
import re
import os

def extract_meaningful_strings(file_path):
    """
    Scans a file's binary content to find and extract significant strings
    like IPs, URLs, emails, and file paths using regular expressions.
    """
    results = {
        "ip_adresses": set(),
        "urls": set(),
        "emails": set(),
        "file_paths": set()
    }
    
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
            
            # Regex patterns definitions
            ip_pattern = rb'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
            url_pattern = rb'https?://[^\s"\'<>]+'
            email_pattern = rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            path_pattern = rb'(?:[a-zA-Z]:\\|\/)[^\s"\'<>]*'
            
            results['ip_adresses'] = {match.decode('ascii', 'ignore') for match in re.findall(ip_pattern, content)}
            results['urls'] = {match.decode('ascii', 'ignore') for match in re.findall(url_pattern, content)}
            results['emails'] = {match.decode('ascii', 'ignore') for match in re.findall(email_pattern, content)}
            results['file_paths'] = {match.decode('ascii', 'ignore') for match in re.findall(path_pattern, content)}

            final_results = {key: list(value) for key, value in results.items() if value}
            
            return final_results
    except Exception as e:
        print(f"[ERROR] Failed to extract meaningful strings: {e}")
        return {"error": str(e)}
    return results

def get_geotagging_info(exif_data):
    """
    Extracts the raw GPS data dictionary from the main EXIF data.
    """
    if not exif_data:
        return None
    try:
        gps_info = {}
        for key, value in exif_data.items():
            tag_name = TAGS.get(key, key)
            if tag_name == 'GPSInfo':
                for gps_key, gps_value in value.items():
                    gps_tag_name = GPSTAGS.get(gps_key, gps_key)
                    gps_info[gps_tag_name] = gps_value
                return gps_info
    except Exception as e: 
        print(f"[ERROR] Failed to extract GPS data: {e}")
    return None

def get_decimal_coordinates(dms, ref):
    """
    Converts coordinates from DMS (degrees, minutes, seconds) to the decimal format.
    """
    degrees = dms[0]
    minutes = dms[1] / 60.0
    seconds = dms[2] / 3600.0
    
    decimal = degrees + minutes + seconds
    
    # South and West coordinates are negative
    if ref in ['S', 'W']:
        decimal = -decimal
    
    return decimal

def get_image_metadata(file_path):
    metadata = {}
    try:
        image = Image.open(file_path)
        metadata['format'] = image.format
        metadata['mode'] = image.mode
        metadata['size'] = f"{image.width}x{image.height}"
        exif_data = image._getexif()
        if exif_data:
            metadata['exif_data'] = {}
            for tag, value in exif_data.items():
                tag_name = TAGS.get(tag, tag)
                metadata['exif_data'][tag_name] = repr(value)
            geotags = get_geotagging_info(exif_data)
            if geotags:
                lat_dms, lon_dms = geotags.get('GPSLatitude'), geotags.get('GPSLongitude')
                lat_ref, lon_ref = geotags.get('GPSLatitudeRef'), geotags.get('GPSLongitudeRef')
                if lat_dms and lon_dms and lat_ref and lon_ref:
                    latitude = get_decimal_coordinates(lat_dms, lat_ref)
                    longitude = get_decimal_coordinates(lon_dms, lon_ref)
                    metadata['geolocation'] = {'latitude': latitude, 'longitude': longitude, 'address': get_address_from_coords(latitude, longitude)}
    except Exception as e:
        metadata['error'] = f"Could not process image file: {e}"
    return metadata

def get_pdf_metadata(file_path):
    metadata = {}
    try:
        with open(file_path, 'rb') as f:
            pdf = PyPDF2.PdfReader(f)
            info = pdf.metadata
            metadata['num_pages'] = len(pdf.pages)
            metadata['author'] = info.author if info.author else 'Unknown'
            metadata['title'] = info.title if info.title else 'Unknown'
            metadata['subject'] = info.subject if info.subject else 'Unknown'
            metadata['producer'] = info.producer if info.producer else 'Unknown'
    except Exception as e:
        metadata['error'] = f"Could not process PDF file: {e}"
    return metadata

def get_adress_from_coordinates(lat, lon):
    """
    Performs reverse geocoding to get a human-readable address from coordinates.
    Requires the 'geopy' library.
    """
    try:
        from geopy.geocoders import Nominatim
        geolocator = Nominatim(user_agent="digital-forensics-tool")
        location = geolocator.reverse((lat, lon), exactly_one=True, language='en')
        return location.address if location else "Address not found"
    except Exception as e:
        print(f"[ERROR] Failed to get address from coordinates: {e}")
        return "Address not found"
    
    
def extract_metadata(file_path):
    """
    Main function that orchestrates metadata extraction.
    It now also calls the string extraction for every file.
    """
    file_extension = os.path.splitext(file_path)[1].lower()
    metadata = {'file_name': os.path.basename(file_path)}
    try:
        if file_extension in ['.jpg', '.jpeg', '.png', '.tiff']:
            metadata.update(get_image_metadata(file_path))
        elif file_extension == '.pdf':
            metadata.update(get_pdf_metadata(file_path))
        else:
            metadata['status'] = 'Unsupported file type for metadata extraction'
        
        # Extract meaningful strings from the file
        strings = extract_meaningful_strings(file_path)
        if strings:
            metadata['meaningful_strings'] = strings 
    except Exception as e:
        return {"error": str(e)}

    return {k: v for k, v in metadata.items() if v is not None}