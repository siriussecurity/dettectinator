import unittest
import os
import sys
import shutil
import subprocess


class TestCli(unittest.TestCase):

    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'unittest_output_cli')
    run_path = os.path.join(os.path.dirname(os.path.abspath(__file__).replace('tests', 'dettectinator')), 'dettectinator.py')

    def setUp(self) -> None:
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
        os.mkdir(self.output_dir)
        return super().setUp()

    def tearDown(self) -> None:
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
        return super().tearDown()

    def test_help(self):
        result = subprocess.run(['python', self.run_path, '-h'], universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertIs(0, result.returncode, msg='CLI help menu is not working')
        self.assertIn('Please specify a valid data import plugin using the "-p" argument', result.stdout, msg='Expecting specific help text')

    def test_csv(self):
        import_filename = os.path.join(self.output_dir, 'import_techniques.csv')
        shutil.copyfile(os.path.join(os.path.dirname(os.path.abspath(__file__).replace('tests', '')), 'examples/import_techniques.csv'), import_filename)
        result = subprocess.run(['python', self.run_path, '-p', 'TechniqueCsv', '-a', 'all', '--file', import_filename], universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=self.output_dir)
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, 'techniques_new.yaml')), msg='Failed save_yaml_file')

    def test_csv_custom_output_filename(self):
        import_filename = os.path.join(self.output_dir, 'import_techniques.csv')
        shutil.copyfile(os.path.join(os.path.dirname(os.path.abspath(__file__).replace('tests', '')), 'examples/import_techniques.csv'), import_filename)
        result = subprocess.run(['python', self.run_path, '-p', 'TechniqueCsv', '-a', 'all', '--file', import_filename, '-o', 'test_csv.yaml'], universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=self.output_dir)
        self.assertTrue(os.path.exists(os.path.join(self.output_dir, 'test_csv.yaml')), msg='Failed save_yaml_file')

if __name__ == '__main__':
    unittest.main()
