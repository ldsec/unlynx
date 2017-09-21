import pandas as pd
pd.options.mode.chained_assignment = None  # default='warn'
pd.set_option('display.max_rows', 200)


def import_data(filename, sep_t):
    """Import csv file"""
    return pd.read_csv(filename, sep=sep_t, low_memory=False)


def protein_position_in_range(protein_position, pos):
    range_protein = str(protein_position).split("/")

    if range_protein[0] != "-" and int(range_protein[0]) == pos:
        return True

    return False


def execute_query_one(clinical_data, genomic_data):

    # ANDs
    # filter the clinical data
    clinical_data = clinical_data[(clinical_data['CANCER_TYPE_DETAILED'] == 'Cutaneous Melanoma') &
                                  (clinical_data['PRIMARY_TUMOR_LOCALIZATION_TYPE'] == 'Skin')]
    clinical_data.reset_index(inplace=True, drop=True)

    # filter the genomic data
    genomic_data = genomic_data[genomic_data['Hugo_Symbol'] == 'BRAF']
    genomic_data.reset_index(inplace=True, drop=True)

    for row in genomic_data['Protein_position']:
        index = 0
        if not protein_position_in_range(row, 600):
            genomic_data.drop(genomic_data.index[[index]], inplace=True)
            index -= 1
        index += 1

    genomic_data.reset_index(inplace=True, drop=True)

    # join tables
    clinical_data = clinical_data[clinical_data['SAMPLE_ID'].isin(genomic_data['Tumor_Sample_Barcode'])]
    clinical_data.reset_index(inplace=True, drop=True)

    return len(clinical_data)


def execute_query_two(clinical_data, genomic_data):

    # ORs
    # filter the genomic data
    or_genomic_data = genomic_data.copy()

    or_genomic_data = or_genomic_data[(or_genomic_data['Hugo_Symbol'] == 'PTEN') |
                                      (or_genomic_data['Hugo_Symbol'] == 'CDKN2A') |
                                      (or_genomic_data['Hugo_Symbol'] == 'MAP2K1') |
                                      (or_genomic_data['Hugo_Symbol'] == 'MAP2K2')]
    or_genomic_data.reset_index(inplace=True, drop=True)

    # ANDs
    # filter the clinical data
    clinical_data = clinical_data[(clinical_data['CANCER_TYPE_DETAILED'] == 'Cutaneous Melanoma') &
                                  (clinical_data['PRIMARY_TUMOR_LOCALIZATION_TYPE'] == 'Skin')]
    clinical_data.reset_index(inplace=True, drop=True)

    # filter the genomic data
    genomic_data = genomic_data[genomic_data['Hugo_Symbol'] == 'BRAF']
    genomic_data.reset_index(inplace=True, drop=True)

    # join tables
    clinical_data = clinical_data[clinical_data['SAMPLE_ID'].isin(genomic_data['Tumor_Sample_Barcode'])]
    clinical_data.reset_index(inplace=True, drop=True)

    # join ANDs and ORs
    clinical_data = clinical_data[clinical_data['SAMPLE_ID'].isin(or_genomic_data['Tumor_Sample_Barcode'])]
    clinical_data.reset_index(inplace=True, drop=True)

    return len(clinical_data)


def execute_query_three(clinical_data):
    # ANDs
    # filter the clinical data
    clinical_data = clinical_data[(clinical_data['GENDER'] == 'Male') &
                                  (clinical_data['PRIMARY_TUMOR_LOCALIZATION_TYPE'] == 'Skin')]

    return len(clinical_data)


if __name__ == '__main__':
    data_clinical_skcm_broad = import_data("datafiles/skcm_broad/data_clinical_skcm_broad.txt", '\t')
    data_mutations_extended_skcm_broad = import_data("datafiles/skcm_broad/data_mutations_extended_skcm_broad.txt", '\t')

    # 1st query
    print "1st query: ", execute_query_one(data_clinical_skcm_broad.copy(), data_mutations_extended_skcm_broad.copy())

    # 2nd query
    print "2nd query: ", execute_query_two(data_clinical_skcm_broad.copy(), data_mutations_extended_skcm_broad.copy())

    # 3rd query
    print "3rd query: ", execute_query_three(data_clinical_skcm_broad.copy())
