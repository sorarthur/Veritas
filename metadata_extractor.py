from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import PyPDF2

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
                    for tag_id, value in exif_data.items():
                        tag = TAGS.get(tag_id, tag_id)
                        metadata[tag] = value
                    
                    # handle GPS data if available
                    if 'GPSInfo' in exif_data:
                        gps_info = {}
                        for key in exif_data['GPSInfo'].keys():
                            decoded_key = GPSTAGS.get(key, key)
                            gps_info[decoded_key] = exif_data['GPSInfo'][key]
                        metadata['GPSInfo'] = gps_info
                        
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
                metadata['created'] = info.created if info.created else 'Unknown'
        else:
            raise ValueError("Unsupported file format. Only images and PDFs are supported.")
        
    except Exception as e:
        return {"error": str(e)}

    return {k: v for k, v in metadata.items() if v is not None}