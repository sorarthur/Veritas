from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import PyPDF2
import geopy

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
    
    
def extract_metadata(image_path):
    metadata = {}
    try:
        # image logic
        if image_path.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
            with Image.open(image_path) as img:
                metadata['format'] = img.format
                metadata['mode'] = img.mode
                metadata['info'] = img.info
                metadata['dimensions'] = f"{img.width}x{img.height}"
                
                # extract EXIF data if available
                exif_data = img._getexif()
                if exif_data:
                    # metadata['exif'] = {}
                    # for tag_id, value in exif_data.items():
                    #     tag = TAGS.get(tag_id, tag_id)
                    #     metadata['exif'][tag] = repr(value)
                    
                    # handle GPS data if available
                    geo_tags = get_geotagging_info(exif_data)
                    if geo_tags:
                        lat_dms = geo_tags.get('GPSLatitude')
                        lon_dms = geo_tags.get('GPSLongitude')
                        lat_dms_ref = geo_tags.get('GPSLatitudeRef')
                        lon_dms_ref = geo_tags.get('GPSLongitudeRef')
                        
                        if lat_dms and lon_dms and lat_dms_ref and lon_dms_ref:
                            latitude = get_decimal_coordinates(lat_dms, lat_dms_ref)
                            longitude = get_decimal_coordinates(lon_dms, lon_dms_ref)
                            
                            metadata['geolocation'] = {
                                'latitude': latitude,
                                'longitude': longitude,
                                'address': get_adress_from_coordinates(latitude, longitude)
                            }
                        
        # pdf logic
        elif image_path.lower().endswith('.pdf'):
            with open(image_path, 'rb') as f:
                pdf = PyPDF2.PdfReader(f)
                info = pdf.metadata
                metadata['format'] = 'PDF'
                metadata['num_pages'] = len(pdf.pages)
                metadata['author'] = info.author if info.author else 'Unknown'
                metadata['title'] = info.title if info.title else 'Unknown'
                metadata['subject'] = info.subject if info.subject else 'Unknown'
                metadata['producer'] = info.producer if info.producer else 'Unknown'
        else:
            raise ValueError("Unsupported file format. Only images and PDFs are supported.")
        
    except Exception as e:
        return {"error": str(e)}

    return {k: v for k, v in metadata.items() if v is not None}